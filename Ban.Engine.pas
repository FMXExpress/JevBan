unit Ban.Engine;

(* One access-log line at a time:

     parse -> ignoreip? -> already banned? -> signature score (+ 4xx flood)
       -> below suspicious_score: just remember it as context
       -> otherwise ask the decider about this client:
            jev:   queue the client; every batch_interval seconds (or
                   batch_lines lines, or batch_clients queued clients) POST
                   all queued clients to /v1/systemone in one request, one
                   question each; per flagged request,
                   P(malicious) >= threshold is a strike,
                   >= instant_threshold bans at once
            rules: score >= rules_min_score is a strike,
                   >= rules_instant_score bans at once
       -> maxretry strikes within findtime: ban for bantime (doubling for
          repeat offenders when bantime.increment is on, up to maxtime)

   A verdict is reused for cache_secs, so a scanner firing 200 probes is one
   question in one batch, not 200 calls; past max_per_minute requests the
   rules decide. Bans survive a restart in the state file.

   The model never overrides the hard rules: a request scoring override_score
   (the weight-10 signatures: /.env, ../, ${jndi:, union select, sqlmap) is a
   strike at once, without a question, so an obvious scanner is banned while
   it is still probing. The model judges the middle ground, and a p between
   review_threshold and threshold is logged as REVIEW. With shadow = 1 the
   model's verdicts are only logged; the rules ban. --eval replays a labelled
   log and counts both against the labels.

   The live daemon asks the decider on a worker thread (TDeciderWorker): a
   batch can take minutes on a CPU, and meanwhile the log is still read, hard
   rules still ban and expired bans are still lifted. --test and --eval ask
   inline, so a replay is deterministic. *)

{$mode objfpc}{$H+}

interface

uses
  SysUtils, Classes, Math, Contnrs, SyncObjs, fpjson, jsonparser,
  Ban.Net, Ban.Apache, Ban.Signatures, Ban.BadPaths, Ban.Jev, Ban.Local, Ban.Firewall, Ban.Config;

const
  { --eval labels }
  CTruthUnknown = -1;
  CTruthBenign = 0;
  CTruthAttack = 1;

type
  { a flagged request waiting for the decider }
  TPendingLine = class
  public
    Summary: string;
    Tags: string;
    Score: Integer;
    Truth: Integer;
    Category: string;
  end;

  { true/false positives and negatives of strike decisions, per request }
  TConfusion = record
    TP, FP, FN, TN: Int64;
  end;

  { --eval: what happened to one labelled client }
  TEvalClient = class
  public
    Attack: Boolean;         { sent at least one attack request }
    Category: string;        { its first attack category, else its benign one }
    Requests: Integer;       { labelled requests seen before any ban }
    AttackRequests: Integer; { ... of which attacks: they reached the server }
    FirstAttack: Int64;      { log time of the first attack request }
    BannedAt: Int64;         { log time of the ban; 0 = not banned }
  end;

  { --eval: per-category request counts }
  TEvalCategory = class
  public
    Rules, Live: TConfusion;
  end;

  TClient = class
  public
    IpText: string;
    Ip: TIpAddr;
    Recent: TStringList;     { request summaries, oldest first }
    Strikes: array of Int64;
    LastSeen: Int64;
    FloodStart: Int64;
    FloodCount: Integer;
    VerdictAt: Int64;        { 0 = no verdict yet }
    VerdictMal: Double;
    VerdictIntent: string;
    Pending: TFPObjectList;  { TPendingLine waiting for the batch }
    PendingTags: TStringList;  { all tags of the pending requests (sent to the decider) }
    PendingSince: Int64;
    Queued: Boolean;
    InFlight: Boolean;       { a batch with this client is with the decider }
    constructor Create;
    destructor Destroy; override;
  end;

  TBanRecord = class
  public
    Ip: TIpAddr;
    IpText: string;
    Since: Int64;
    Expires: Int64;
    Count: Integer;          { bans so far: bantime.increment }
    Active: Boolean;
    Reason: string;
  end;

  { one batch for the decider: the clients, what the model sees, the verdicts }
  TDecideJob = class
  public
    Clients: TList;          { TClient, kept alive by InFlight }
    Lines: TFPObjectList;    { per client, a TFPObjectList of its TPendingLine }
    Items: TList;            { TJevItem, one per client }
    Ok: Boolean;
    Error: string;
    Ms: Int64;
    constructor Create;
    destructor Destroy; override;
  end;

  { asks the decider on its own thread: jobs in, finished jobs out }
  TDeciderWorker = class(TThread)
  private
    FDecider: TDecider;
    FLock: TCriticalSection;
    FTodo, FDone: TList;
    FWake: TEventObject;
  protected
    procedure Execute; override;
  public
    constructor Create(ADecider: TDecider);
    destructor Destroy; override;
    procedure Submit(AJob: TDecideJob);
    { a finished job, or nil }
    function Collect: TDecideJob;
    function Busy: Integer;
  end;

  TBanStats = record
    Lines, Parsed, Ignored, Suspicious, HardRules, DeciderCalls, DeciderClients, DeciderErrors,
      Reviews, Strikes, Bans, Unbans: Int64;
  end;

  TBanEngine = class
  private
    FCfg: TBanConfig;
    FSigs: TSignatureSet;
    FDecider: TDecider;      { nil in rules mode, or when the local model could not be loaded }
    FAction: TBanAction;
    FClients: TStringList;   { ip -> TClient }
    FBans: TStringList;      { ip -> TBanRecord }
    FMinute: Int64;
    FMinuteCalls: Integer;
    FLastPurge: Int64;
    FLastErrLog: Int64;
    FErrsSinceLog: Integer;
    FDirty: Boolean;
    FLog: TFileStream;
    FQueue: TList;           { TClient waiting for the next batch, oldest first }
    FLinesSinceFlush: Integer;
    FLastNow: Int64;
    FBad: TBadPaths;         { nil when badpaths = off }
    FWorker: TDeciderWorker; { live daemon only }
    { --eval: strike decisions per labelled request, rules alone and the whole pipeline }
    FEvalRules, FEvalLive: TConfusion;
    FEvalAfterBan: array[CTruthBenign..CTruthAttack] of Int64;
    FEvalClients: TStringList;   { ip -> TEvalClient }
    FEvalCats: TStringList;      { category -> TEvalCategory }
    FEvalStart: TDateTime;
    procedure Count(var AConf: TConfusion; ATruth: Integer; AStrike: Boolean);
    { one labelled request decided: rules alone, and the live pipeline }
    procedure CountEval(ATruth: Integer; const ACategory: string; ARulesStrike, ALiveStrike: Boolean);
    function GetClient(const E: TAccessEntry; ANow: Int64): TClient;
    procedure Judge(C: TClient; const ASummary, ATags: string; AScore, ATruth: Integer;
      const ACategory: string; ANow: Int64);
    { the one place a flagged request is decided. AMal < 0: no model verdict
      (rules mode, a hard rule, the decider unavailable) }
    procedure Decide(C: TClient; const ASummary, ATags: string; AScore, ATruth: Integer;
      const ACategory: string; AMal: Double; const AIntent, AHow: string; ANow: Int64);
    function IsBanned(const AIp: string): Boolean;
    procedure MaybeFlush(ANow: Int64);
    procedure Flush(ANow: Int64);
    procedure ApplyJob(AJob: TDecideJob; ANow: Int64);
    procedure CollectResults;
    procedure AddStrike(C: TClient; ANow: Int64; AInstant: Boolean; const AReason: string);
    procedure BanClient(C: TClient; const AReason: string);
    procedure Purge(ANow: Int64);
    procedure EvictOldest(ACount: Integer);
    procedure LoadState;
    procedure SaveState;
  public
    Stats: TBanStats;
    constructor Create(ACfg: TBanConfig);
    destructor Destroy; override;
    procedure Log(const AMsg: string);
    { state, actionstart, re-ban what is still banned }
    procedure Start;
    { state, actionstop when cleanup_on_exit }
    procedure Stop;
    { ATruth: a --eval label (CTruth*) }
    procedure Feed(const ALine: string; ATruth: Integer = CTruthUnknown; const ACategory: string = '');
    { --eval: the counts against the labels; AJsonFile <> '': also as JSON }
    procedure EvalReport(const AJsonFile: string = '');
    { unbans the expired, forgets idle clients, saves the state }
    procedure Tick;
    { the remote client, or the local model (downloaded on first use); on
      failure logs why and leaves the rules to decide }
    procedure InitDecider;
    { asks the decider about everything still queued (end of --test) }
    procedure FlushAll;
    function Describe: string;
    procedure PrintBans;
    function Summary: string;
  end;

implementation

{ TClient }

constructor TClient.Create;
begin
  inherited Create;
  Recent := TStringList.Create;
  Pending := TFPObjectList.Create(True);
  PendingTags := TStringList.Create;
end;

destructor TClient.Destroy;
begin
  PendingTags.Free;
  Pending.Free;
  Recent.Free;
  inherited Destroy;
end;

{ TDecideJob }

constructor TDecideJob.Create;
begin
  inherited Create;
  Clients := TList.Create;
  Lines := TFPObjectList.Create(True);
  Items := TList.Create;
end;

destructor TDecideJob.Destroy;
var
  I: Integer;
begin
  for I := 0 to Items.Count - 1 do
    TJevItem(Items[I]).Free;
  Items.Free;
  Lines.Free;
  Clients.Free;
  inherited Destroy;
end;

{ TDeciderWorker }

constructor TDeciderWorker.Create(ADecider: TDecider);
begin
  FDecider := ADecider;
  FLock := TCriticalSection.Create;
  FTodo := TList.Create;
  FDone := TList.Create;
  FWake := TEventObject.Create(nil, False, False, '');
  inherited Create(False);
end;

destructor TDeciderWorker.Destroy;
var
  I: Integer;
begin
  Terminate;
  FWake.SetEvent;
  WaitFor;
  for I := 0 to FTodo.Count - 1 do
    TDecideJob(FTodo[I]).Free;
  for I := 0 to FDone.Count - 1 do
    TDecideJob(FDone[I]).Free;
  FTodo.Free;
  FDone.Free;
  FWake.Free;
  FLock.Free;
  inherited Destroy;
end;

procedure TDeciderWorker.Execute;
var
  LJob: TDecideJob;
begin
  { the FPU mask is per thread, and ggml's kernels need the C default }
  SetExceptionMask([exInvalidOp, exDenormalized, exZeroDivide, exOverflow, exUnderflow, exPrecision]);
  while not Terminated do
  begin
    FLock.Enter;
    try
      if FTodo.Count > 0 then
      begin
        LJob := TDecideJob(FTodo[0]);
        FTodo.Delete(0);
      end
      else
        LJob := nil;
    finally
      FLock.Leave;
    end;
    if LJob = nil then
    begin
      FWake.WaitFor(500);
      Continue;
    end;
    LJob.Ok := FDecider.Decide(LJob.Items, LJob.Error, LJob.Ms);
    FLock.Enter;
    try
      FDone.Add(LJob);
    finally
      FLock.Leave;
    end;
  end;
end;

procedure TDeciderWorker.Submit(AJob: TDecideJob);
begin
  FLock.Enter;
  try
    FTodo.Add(AJob);
  finally
    FLock.Leave;
  end;
  FWake.SetEvent;
end;

function TDeciderWorker.Collect: TDecideJob;
begin
  Result := nil;
  FLock.Enter;
  try
    if FDone.Count > 0 then
    begin
      Result := TDecideJob(FDone[0]);
      FDone.Delete(0);
    end;
  finally
    FLock.Leave;
  end;
end;

function TDeciderWorker.Busy: Integer;
begin
  FLock.Enter;
  try
    Result := FTodo.Count;
  finally
    FLock.Leave;
  end;
end;

{ TBanEngine }

constructor TBanEngine.Create(ACfg: TBanConfig);
begin
  inherited Create;
  FCfg := ACfg;
  FSigs := TSignatureSet.Create(FCfg.BuiltinSignatures);
  if FCfg.SignatureFile <> '' then
    FSigs.LoadFile(FCfg.SignatureFile);
  FQueue := TList.Create;
  if FCfg.BadPathsFile <> '' then
  begin
    FBad := TBadPaths.Create;
    FBad.LoadFile(FCfg.BadPathsFile);
  end;
  FEvalClients := TStringList.Create;
  FEvalClients.Sorted := True;
  FEvalClients.OwnsObjects := True;
  FEvalCats := TStringList.Create;
  FEvalCats.Sorted := True;
  FEvalCats.OwnsObjects := True;
  FEvalStart := Now;
  FAction := TBanAction.Create(@Log);
  FAction.Kind := FCfg.ActionType;
  FAction.Name := FCfg.ActionName;
  FAction.Port := FCfg.Port;
  FAction.Jail := FCfg.Jail;
  FAction.StartCmd := FCfg.ActionStart;
  FAction.StopCmd := FCfg.ActionStop;
  FAction.BanCmd := FCfg.ActionBan;
  FAction.UnbanCmd := FCfg.ActionUnban;
  FAction.DryRun := FCfg.DryRun;
  FAction.ApplyPreset;
  FClients := TStringList.Create;
  FClients.Sorted := True;
  FClients.OwnsObjects := True;
  FBans := TStringList.Create;
  FBans.Sorted := True;
  FBans.OwnsObjects := True;
  if (FCfg.LogFile <> '') and not FCfg.TestMode then
  begin
    ForceDirectories(ExtractFileDir(ExpandFileName(FCfg.LogFile)));
    if FileExists(FCfg.LogFile) then
      FLog := TFileStream.Create(FCfg.LogFile, fmOpenWrite or fmShareDenyNone)
    else
      FLog := TFileStream.Create(FCfg.LogFile, fmCreate);
    FLog.Seek(0, soEnd);
  end;
end;

destructor TBanEngine.Destroy;
begin
  FWorker.Free;   { before the decider it uses }
  FLog.Free;
  FEvalClients.Free;
  FEvalCats.Free;
  FBad.Free;
  FQueue.Free;
  FBans.Free;
  FClients.Free;
  FAction.Free;
  FDecider.Free;
  FSigs.Free;
  inherited Destroy;
end;

procedure TBanEngine.Log(const AMsg: string);
var
  LLine: string;
begin
  LLine := FormatDateTime('yyyy-mm-dd hh:nn:ss', Now) + ' jevban: ' + AMsg;
  WriteLn(LLine);
  System.Flush(Output);
  if FLog <> nil then
  begin
    LLine := LLine + LineEnding;
    FLog.WriteBuffer(LLine[1], Length(LLine));
  end;
end;

procedure TBanEngine.EvictOldest(ACount: Integer);
var
  LSeen: array of Int64;
  I, N: Integer;
  LCutoff: Int64;

  procedure Sort(L, R: Integer);
  var
    I, J: Integer;
    P, T: Int64;
  begin
    while L < R do
    begin
      I := L;
      J := R;
      P := LSeen[(L + R) div 2];
      repeat
        while LSeen[I] < P do
          Inc(I);
        while LSeen[J] > P do
          Dec(J);
        if I <= J then
        begin
          T := LSeen[I];
          LSeen[I] := LSeen[J];
          LSeen[J] := T;
          Inc(I);
          Dec(J);
        end;
      until I > J;
      if J - L < R - I then
      begin
        Sort(L, J);
        L := I;
      end
      else
      begin
        Sort(I, R);
        R := J;
      end;
    end;
  end;

begin
  N := FClients.Count;
  SetLength(LSeen, N);
  for I := 0 to N - 1 do
    LSeen[I] := TClient(FClients.Objects[I]).LastSeen;
  Sort(0, N - 1);
  LCutoff := LSeen[Min(ACount, N) - 1];
  for I := N - 1 downto 0 do
    if (TClient(FClients.Objects[I]).LastSeen <= LCutoff) and not TClient(FClients.Objects[I]).Queued and
       not TClient(FClients.Objects[I]).InFlight then
      FClients.Delete(I);
end;

function TBanEngine.GetClient(const E: TAccessEntry; ANow: Int64): TClient;
var
  I: Integer;
begin
  I := FClients.IndexOf(E.IpText);
  if I >= 0 then
    Exit(TClient(FClients.Objects[I]));
  if FClients.Count >= FCfg.MaxClients then
  begin
    Purge(ANow);
    if FClients.Count >= FCfg.MaxClients then
      { still full (a flood of new addresses): drop the oldest tenth in one pass,
        so the next inserts don't each scan the whole table }
      EvictOldest(Max(1, FClients.Count div 10));
  end;
  Result := TClient.Create;
  Result.IpText := E.IpText;
  Result.Ip := E.Ip;
  FClients.AddObject(E.IpText, Result);
end;

procedure TBanEngine.Feed(const ALine: string; ATruth: Integer; const ACategory: string);
var
  E: TAccessEntry;
  C: TClient;
  LNow: Int64;
  LTags: TStringList;
  LScore, I, LDist: Integer;
  LSummary, LPath, LNear: string;
  LEval: TEvalClient;
begin
  Inc(Stats.Lines);
  if not ParseAccessLine(ALine, E) then
  begin
    if FCfg.Verbose then
      Log('unparsed: ' + Copy(ALine, 1, 200));
    Exit;
  end;
  Inc(Stats.Parsed);
  if InCidrList(FCfg.IgnoreIp, E.Ip) then
  begin
    Inc(Stats.Ignored);
    Exit;
  end;
  { replaying a file (--test) runs on the log's clock, live on the wall clock }
  if FCfg.TestMode and (E.Epoch > 0) then
    LNow := E.Epoch
  else
    LNow := UnixNow;
  LEval := nil;
  if ATruth <> CTruthUnknown then
  begin
    I := FEvalClients.IndexOf(E.IpText);
    if I < 0 then
    begin
      LEval := TEvalClient.Create;
      LEval.Category := ACategory;
      FEvalClients.AddObject(E.IpText, LEval);
    end
    else
      LEval := TEvalClient(FEvalClients.Objects[I]);
    if (ATruth = CTruthAttack) and not LEval.Attack then
    begin
      LEval.Attack := True;
      LEval.Category := ACategory;
      LEval.FirstAttack := LNow;
    end;
    if not IsBanned(E.IpText) then
    begin
      Inc(LEval.Requests);
      if ATruth = CTruthAttack then
        Inc(LEval.AttackRequests);
    end;
  end;
  FLastNow := LNow;
  if FQueue.Count > 0 then
    Inc(FLinesSinceFlush);
  if IsBanned(E.IpText) then
  begin
    { already banned: a connection that was open before the ban }
    if ATruth <> CTruthUnknown then
      Inc(FEvalAfterBan[ATruth]);
    Exit;
  end;
  C := GetClient(E, LNow);
  C.LastSeen := LNow;
  LSummary := EntrySummary(E);
  LTags := TStringList.Create;
  try
    LTags.Duplicates := dupIgnore;
    LScore := FSigs.Score(E, LTags);
    if FBad <> nil then
    begin
      { a known-bad path: a probe when it is not there, the decider's call when it is }
      LPath := NormalizePath(E.Decoded);
      if FBad.IsExact(LPath) then
      begin
        if E.Status >= 400 then
        begin
          Inc(LScore, 6);
          LTags.Add('known-bad-path');
        end
        else if Pos('.', LPath) > 0 then
        begin
          { served: a file that should not exist here (/phpinfo.php, /.env, /backup.zip).
            A plain route that is served (/search, /download) is the site's own page:
            on the LogarX shop those were 242 benign requests against 66 attacks }
          Inc(LScore, 3);
          LTags.Add('known-bad-path-served');
        end;
      end
      else if (E.Status >= 400) and (E.Status < 500) then
      begin
        LNear := FBad.Near(LPath, LDist);
        if LNear <> '' then
        begin
          Inc(LScore, 3);
          LTags.Add('near-known-bad');
          if FCfg.Verbose then
            Log(Format('%s %s is %d edit(s) from %s', [E.IpText, LPath, LDist, LNear]));
        end;
      end;
    end;
    if (FCfg.Flood4xx > 0) and (E.Status >= 400) and (E.Status < 500) then
    begin
      if LNow - C.FloodStart > FCfg.FindTime then
      begin
        C.FloodStart := LNow;
        C.FloodCount := 0;
      end;
      Inc(C.FloodCount);
      if C.FloodCount = FCfg.Flood4xx then
      begin
        Inc(LScore, 6);
        LTags.Add('4xx-flood');
      end;
    end;
    if LScore >= FCfg.SuspiciousScore then
    begin
      Inc(Stats.Suspicious);
      Judge(C, LSummary, LTags.CommaText, LScore, ATruth, ACategory, LNow);
    end
    else
      { not flagged: neither rules nor model strike }
      CountEval(ATruth, ACategory, False, False);
  finally
    LTags.Free;
  end;
  C.Recent.Add(LSummary);
  while C.Recent.Count > FCfg.ContextLines do
    C.Recent.Delete(0);
  MaybeFlush(LNow);
end;

function TBanEngine.IsBanned(const AIp: string): Boolean;
var
  I: Integer;
begin
  I := FBans.IndexOf(AIp);
  Result := (I >= 0) and TBanRecord(FBans.Objects[I]).Active;
end;

procedure TBanEngine.Judge(C: TClient; const ASummary, ATags: string; AScore, ATruth: Integer;
  const ACategory: string; ANow: Int64);
var
  LLine: TPendingLine;
  LTag: string;
  LTagList: TStringList;
begin
  if FDecider = nil then
  begin
    Decide(C, ASummary, ATags, AScore, ATruth, ACategory, -1, '', 'rules', ANow);
    Exit;
  end;
  { the model never overrides a hard rule, and is not asked about one }
  if (FCfg.OverrideScore > 0) and (AScore >= FCfg.OverrideScore) then
  begin
    Inc(Stats.HardRules);
    Decide(C, ASummary, ATags, AScore, ATruth, ACategory, -1, '', 'hard rule', ANow);
    Exit;
  end;
  if (C.VerdictAt > 0) and (ANow - C.VerdictAt < FCfg.CacheSecs) and not C.Queued and not C.InFlight then
  begin
    Decide(C, ASummary, ATags, AScore, ATruth, ACategory, C.VerdictMal, C.VerdictIntent,
      FCfg.Mode + ' (cached)', ANow);
    Exit;
  end;
  { the next batch decides }
  if not C.Queued then
  begin
    C.Queued := True;
    C.PendingSince := ANow;
    FQueue.Add(C);
  end;
  LLine := TPendingLine.Create;
  LLine.Summary := ASummary;
  LLine.Tags := ATags;
  LLine.Score := AScore;
  LLine.Truth := ATruth;
  LLine.Category := ACategory;
  C.Pending.Add(LLine);
  LTagList := TStringList.Create;
  try
    LTagList.CommaText := ATags;
    for LTag in LTagList do
      if C.PendingTags.IndexOf(LTag) < 0 then
        C.PendingTags.Add(LTag);
  finally
    LTagList.Free;
  end;
  if FCfg.Verbose then
    Log(Format('%s queued (%d in batch) score=%d [%s]: %s', [C.IpText, FQueue.Count, AScore,
      ATags, Copy(ASummary, 1, 300)]));
end;

procedure TBanEngine.Count(var AConf: TConfusion; ATruth: Integer; AStrike: Boolean);
begin
  if ATruth = CTruthAttack then
  begin
    if AStrike then
      Inc(AConf.TP)
    else
      Inc(AConf.FN);
  end
  else if ATruth = CTruthBenign then
  begin
    if AStrike then
      Inc(AConf.FP)
    else
      Inc(AConf.TN);
  end;
end;

procedure TBanEngine.CountEval(ATruth: Integer; const ACategory: string; ARulesStrike, ALiveStrike: Boolean);
var
  I: Integer;
  LCat: TEvalCategory;
begin
  if ATruth = CTruthUnknown then
    Exit;
  Count(FEvalRules, ATruth, ARulesStrike);
  Count(FEvalLive, ATruth, ALiveStrike);
  if ACategory = '' then
    Exit;
  I := FEvalCats.IndexOf(ACategory);
  if I < 0 then
  begin
    LCat := TEvalCategory.Create;
    FEvalCats.AddObject(ACategory, LCat);
  end
  else
    LCat := TEvalCategory(FEvalCats.Objects[I]);
  Count(LCat.Rules, ATruth, ARulesStrike);
  Count(LCat.Live, ATruth, ALiveStrike);
end;

procedure TBanEngine.Decide(C: TClient; const ASummary, ATags: string; AScore, ATruth: Integer;
  const ACategory: string; AMal: Double; const AIntent, AHow: string; ANow: Int64);
var
  LRulesStrike, LRulesInstant, LModelStrike, LModelInstant, LReview, LStrike, LInstant: Boolean;
  LVerdict, LModel, LReason: string;
begin
  LRulesStrike := AScore >= FCfg.RulesMinScore;
  LRulesInstant := AScore >= FCfg.RulesInstantScore;
  LModelStrike := (AMal >= 0) and (AMal >= FCfg.Threshold);
  LModelInstant := (AMal >= 0) and (AMal >= FCfg.InstantThreshold);
  LReview := (AMal >= 0) and not LModelStrike and (FCfg.ReviewThreshold > 0) and (AMal >= FCfg.ReviewThreshold);
  if (AMal < 0) or FCfg.Shadow then
  begin
    LStrike := LRulesStrike;
    LInstant := LRulesInstant;
  end
  else
  begin
    LStrike := LModelStrike;
    LInstant := LModelInstant;
  end;
  CountEval(ATruth, ACategory, LRulesStrike, LStrike);

  if LInstant then
    LVerdict := 'BAN'
  else if LStrike then
    LVerdict := Format('strike %d/%d', [Length(C.Strikes) + 1, FCfg.MaxRetry])
  else if LReview and not FCfg.Shadow then
    LVerdict := 'REVIEW'
  else
    LVerdict := 'pass';
  if LReview then
    Inc(Stats.Reviews);
  LModel := '';
  if AMal >= 0 then
  begin
    LModel := Format(' p=%.2f%s', [AMal, BoolToStr(AIntent <> '', ' intent=' + AIntent, '')]);
    if FCfg.Shadow then
    begin
      if LModelInstant then
        LModel := LModel + ' (shadow: model says BAN)'
      else if LModelStrike then
        LModel := LModel + ' (shadow: model says strike)'
      else if LReview then
        LModel := LModel + ' (shadow: model says REVIEW)'
      else
        LModel := LModel + ' (shadow: model says pass)';
    end;
  end;
  if FCfg.Verbose or FCfg.TestMode or LStrike or LReview or (FCfg.Shadow and (LModelStrike <> LStrike)) then
    Log(Format('%s %s score=%d [%s]%s via %s: %s', [C.IpText, LVerdict, AScore, ATags, LModel, AHow,
      Copy(ASummary, 1, 300)]));
  if LStrike then
  begin
    if (AMal >= 0) and not FCfg.Shadow then
      LReason := Format('%s, p=%.2f%s', [ATags, AMal, BoolToStr(AIntent <> '', ' ' + AIntent, '')])
    else
      LReason := Format('%s, score %d', [ATags, AScore]);
    AddStrike(C, ANow, LInstant, LReason);
  end;
end;

procedure TBanEngine.MaybeFlush(ANow: Int64);
begin
  if FQueue.Count = 0 then
    Exit;
  if (FQueue.Count >= FCfg.BatchClients) or (FLinesSinceFlush >= FCfg.BatchLines) or
     (ANow - TClient(FQueue[0]).PendingSince >= FCfg.BatchInterval) then
    Flush(ANow);
end;

procedure TBanEngine.Flush(ANow: Int64);
var
  LJob: TDecideJob;
  LItem: TJevItem;
  C: TClient;
  J: Integer;
begin
  while FQueue.Count > 0 do
  begin
    LJob := TDecideJob.Create;
    while (FQueue.Count > 0) and (LJob.Clients.Count < FCfg.BatchClients) do
    begin
      C := TClient(FQueue[0]);
      FQueue.Delete(0);
      LJob.Clients.Add(C);
      LItem := TJevItem.Create;
      LItem.Ip := C.IpText;
      LItem.Hits := C.PendingTags.CommaText;
      { the model sees the latest flagged requests; all of them get its verdict }
      for J := Max(0, C.Pending.Count - 2 * FCfg.ContextLines) to C.Pending.Count - 1 do
        LItem.Flagged.Add(TPendingLine(C.Pending[J]).Summary);
      for J := 0 to C.Recent.Count - 1 do
        if LItem.Flagged.IndexOf(C.Recent[J]) < 0 then
          LItem.Earlier.Add(C.Recent[J]);
      LJob.Items.Add(LItem);
      { the job takes the client's pending requests }
      LJob.Lines.Add(C.Pending);
      C.Pending := TFPObjectList.Create(True);
      C.PendingTags.Clear;
      C.Queued := False;
    end;

    if ANow div 60 <> FMinute then
    begin
      FMinute := ANow div 60;
      FMinuteCalls := 0;
    end;
    if FMinuteCalls >= FCfg.MaxPerMinute then
    begin
      LJob.Error := 'rate limit';
      ApplyJob(LJob, ANow);
      Continue;
    end;
    Inc(FMinuteCalls);
    Inc(Stats.DeciderCalls);
    Inc(Stats.DeciderClients, LJob.Items.Count);
    if FWorker <> nil then
    begin
      for J := 0 to LJob.Clients.Count - 1 do
        TClient(LJob.Clients[J]).InFlight := True;
      FWorker.Submit(LJob);
    end
    else
    begin
      LJob.Ok := FDecider.Decide(LJob.Items, LJob.Error, LJob.Ms);
      ApplyJob(LJob, ANow);
    end;
  end;
  FLinesSinceFlush := 0;
end;

procedure TBanEngine.ApplyJob(AJob: TDecideJob; ANow: Int64);
var
  LItem: TJevItem;
  LLine: TPendingLine;
  LLines: TFPObjectList;
  C: TClient;
  I, J: Integer;
  LHow: string;
begin
  try
    if AJob.Error = 'rate limit' then
      LHow := 'rules (decider rate limit)'
    else if AJob.Ok then
      LHow := Format('%s batch of %d, %dms', [FCfg.Mode, AJob.Items.Count, AJob.Ms])
    else
    begin
      Inc(Stats.DeciderErrors);
      Inc(FErrsSinceLog);
      if UnixNow - FLastErrLog >= 60 then
      begin
        Log(Format('decider error (%d since last report): %s', [FErrsSinceLog, AJob.Error]));
        FLastErrLog := UnixNow;
        FErrsSinceLog := 0;
      end;
      if FCfg.OnError = 'rules' then
        LHow := 'rules (decider unavailable)'
      else
        LHow := 'skipped (decider unavailable)';
    end;

    for I := 0 to AJob.Clients.Count - 1 do
    begin
      C := TClient(AJob.Clients[I]);
      LItem := TJevItem(AJob.Items[I]);
      LLines := TFPObjectList(AJob.Lines[I]);
      C.InFlight := False;
      if AJob.Ok then
      begin
        C.VerdictAt := ANow;
        C.VerdictMal := LItem.Malicious;
        C.VerdictIntent := LItem.Intent;
      end;
      for J := 0 to LLines.Count - 1 do
      begin
        LLine := TPendingLine(LLines[J]);
        if IsBanned(C.IpText) then
        begin
          if LLine.Truth <> CTruthUnknown then
            Inc(FEvalAfterBan[LLine.Truth]);
          Continue;
        end;
        if AJob.Ok then
          Decide(C, LLine.Summary, LLine.Tags, LLine.Score, LLine.Truth, LLine.Category, LItem.Malicious,
            LItem.Intent, LHow, ANow)
        else if (AJob.Error = 'rate limit') or (FCfg.OnError = 'rules') then
          Decide(C, LLine.Summary, LLine.Tags, LLine.Score, LLine.Truth, LLine.Category, -1, '', LHow, ANow)
        else
        begin
          CountEval(LLine.Truth, LLine.Category, LLine.Score >= FCfg.RulesMinScore, False);
          if FCfg.Verbose or FCfg.TestMode then
            Log(Format('%s pass [%s] via %s: %s', [C.IpText, LLine.Tags, LHow, Copy(LLine.Summary, 1, 300)]));
        end;
      end;
      { requests that came in while the batch was out: the fresh verdict covers them }
      if AJob.Ok and C.Queued then
      begin
        for J := 0 to C.Pending.Count - 1 do
        begin
          LLine := TPendingLine(C.Pending[J]);
          if IsBanned(C.IpText) then
          begin
            if LLine.Truth <> CTruthUnknown then
              Inc(FEvalAfterBan[LLine.Truth]);
            Continue;
          end;
          Decide(C, LLine.Summary, LLine.Tags, LLine.Score, LLine.Truth, LLine.Category, LItem.Malicious,
            LItem.Intent, FCfg.Mode + ' (verdict of the batch in flight)', ANow);
        end;
        C.Pending.Clear;
        C.PendingTags.Clear;
        C.Queued := False;
        FQueue.Remove(C);
      end;
    end;
  finally
    AJob.Free;
  end;
end;

procedure TBanEngine.CollectResults;
var
  LJob: TDecideJob;
begin
  if FWorker = nil then
    Exit;
  repeat
    LJob := FWorker.Collect;
    if LJob <> nil then
      ApplyJob(LJob, UnixNow);
  until LJob = nil;
end;

procedure TBanEngine.InitDecider;
var
  LJev: TJevClient;
  LLocal: TLocalJudge;
  LInfo: TLocalModelInfo;
  LPath: string;
begin
  if FCfg.Mode = 'jev' then
  begin
    LJev := TJevClient.Create;
    LJev.Url := FCfg.JevUrl;
    LJev.ApiKey := FCfg.JevKey;
    LJev.Model := FCfg.JevModel;
    LJev.Site := FCfg.Site;
    LJev.Question := FCfg.Question;
    LJev.TimeoutMs := FCfg.TimeoutMs;
    LJev.AskIntent := FCfg.AskIntent;
    FDecider := LJev;
  end
  else if FCfg.Mode = 'local' then
  try
    LPath := EnsureLocalModel(FCfg.LocalModel, FCfg.ModelDir, @Log);
    Log('loading ' + LPath);
    LLocal := TLocalJudge.Create(LPath, FCfg.LlamaLibDir, FCfg.Threads, FCfg.GpuLayers, FCfg.CtxTokens);
    LLocal.Site := FCfg.Site;
    LLocal.Question := FCfg.Question;
    LLocal.AskIntent := FCfg.AskIntent;
    { the calibration of the model's family, unless the config sets its own }
    if not FindLocalModel(FCfg.LocalModel, LInfo) then
      FindLocalModel('flash-9b', LInfo);
    LLocal.T := IfThen(FCfg.ReadoutT > 0, FCfg.ReadoutT, LInfo.T);
    LLocal.NoulT := IfThen(FCfg.NoulT > 0, FCfg.NoulT, LInfo.NoulT);
    if IsNan(FCfg.NoulBias) then
      LLocal.NoulBias := LInfo.NoulBias
    else
      LLocal.NoulBias := FCfg.NoulBias;
    FDecider := LLocal;
  except
    on E: Exception do
      Log(Format('local model unavailable, the signatures decide instead: %s', [E.Message]));
  end;
  { the live daemon asks on a worker thread; --test and --eval inline }
  if (FDecider <> nil) and not FCfg.TestMode then
    FWorker := TDeciderWorker.Create(FDecider);
end;

function TBanEngine.Describe: string;
begin
  if FDecider <> nil then
    Result := FDecider.Describe
  else
    Result := 'rules';
end;

function Median(var A: array of Double): Double;
var
  I, J: Integer;
  T: Double;
begin
  if Length(A) = 0 then
    Exit(0);
  for I := 1 to High(A) do
  begin
    T := A[I];
    J := I - 1;
    while (J >= 0) and (A[J] > T) do
    begin
      A[J + 1] := A[J];
      Dec(J);
    end;
    A[J + 1] := T;
  end;
  if Length(A) mod 2 = 1 then
    Result := A[High(A) div 2]
  else
    Result := (A[Length(A) div 2 - 1] + A[Length(A) div 2]) / 2;
end;

procedure TBanEngine.EvalReport(const AJsonFile: string);

  function Pct(A, B: Int64): string;
  begin
    if B = 0 then
      Result := '   -  '
    else
      Result := Format('%5.1f%%', [100 * A / B]);
  end;

  function Ratio(A, B: Int64): Double;
  begin
    if B = 0 then
      Result := -1
    else
      Result := A / B;
  end;

  procedure Row(const AName: string; const C: TConfusion);
  begin
    WriteLn(Format('  %-26s %5d %5d %5d %5d   %s   %s', [AName, C.TP, C.FP, C.FN, C.TN,
      Pct(C.TP, C.TP + C.FP), Pct(C.TP, C.TP + C.FN)]));
  end;

  function ConfJson(const C: TConfusion): TJSONObject;
  begin
    Result := TJSONObject.Create(['tp', C.TP, 'fp', C.FP, 'fn', C.FN, 'tn', C.TN,
      'precision', Ratio(C.TP, C.TP + C.FP), 'recall', Ratio(C.TP, C.TP + C.FN)]);
  end;

var
  I, J, LAttack, LBenign, LAttackBanned, LBenignBanned, LCatClients, LCatBanned: Integer;
  LLeaked: Int64;
  LEval: TEvalClient;
  LCat: TEvalCategory;
  LLeakedEach, LSecs: array of Double;
  LRoot, LCats, LObj: TJSONObject;
  LText: TStringList;
  LLive: string;
begin
  LAttack := 0;
  LBenign := 0;
  LAttackBanned := 0;
  LBenignBanned := 0;
  LLeaked := 0;
  LLeakedEach := nil;
  LSecs := nil;
  for I := 0 to FEvalClients.Count - 1 do
  begin
    LEval := TEvalClient(FEvalClients.Objects[I]);
    if LEval.Attack then
    begin
      Inc(LAttack);
      Inc(LLeaked, LEval.AttackRequests);
      if LEval.BannedAt > 0 then
      begin
        Inc(LAttackBanned);
        SetLength(LLeakedEach, Length(LLeakedEach) + 1);
        LLeakedEach[High(LLeakedEach)] := LEval.AttackRequests;
        SetLength(LSecs, Length(LSecs) + 1);
        LSecs[High(LSecs)] := Max(0, LEval.BannedAt - LEval.FirstAttack);
      end;
    end
    else
    begin
      Inc(LBenign);
      if LEval.BannedAt > 0 then
        Inc(LBenignBanned);
    end;
  end;
  if FDecider <> nil then
    LLive := BoolToStr(FCfg.Shadow, 'live (shadow: rules)', 'live (hard rules+model)')
  else
    LLive := 'live (rules)';

  WriteLn;
  WriteLn('Strike decisions per labelled request (attack = positive):');
  WriteLn('                                TP    FP    FN    TN   precision  recall');
  Row('signatures only', FEvalRules);
  Row(LLive, FEvalLive);
  WriteLn(Format('  requests after the client was banned: %d attack (stopped), %d benign (lost)',
    [FEvalAfterBan[CTruthAttack], FEvalAfterBan[CTruthBenign]]));
  WriteLn(Format('Clients: %d of %d attackers banned; %d of %d benign clients banned (false bans)',
    [LAttackBanned, LAttack, LBenignBanned, LBenign]));
  WriteLn(Format('  attack requests that reached the server: %d; per banned attacker, median %.1f, ' +
    'median %.0f s from first attack to ban', [LLeaked, Median(LLeakedEach), Median(LSecs)]));
  if FEvalCats.Count > 0 then
  begin
    WriteLn('Per category (live):            clients banned   requests caught/flagged');
    for I := 0 to FEvalCats.Count - 1 do
    begin
      LCat := TEvalCategory(FEvalCats.Objects[I]);
      LCatClients := 0;
      LCatBanned := 0;
      for J := 0 to FEvalClients.Count - 1 do
        if TEvalClient(FEvalClients.Objects[J]).Category = FEvalCats[I] then
        begin
          Inc(LCatClients);
          Inc(LCatBanned, Ord(TEvalClient(FEvalClients.Objects[J]).BannedAt > 0));
        end;
      if LCat.Live.TP + LCat.Live.FN > 0 then
        WriteLn(Format('  %-28s %4d / %-4d     %d of %d attack requests', [FEvalCats[I], LCatBanned,
          LCatClients, LCat.Live.TP, LCat.Live.TP + LCat.Live.FN]))
      else
        WriteLn(Format('  %-28s %4d / %-4d     %d of %d benign requests struck', [FEvalCats[I], LCatBanned,
          LCatClients, LCat.Live.FP, LCat.Live.FP + LCat.Live.TN]));
    end;
  end;
  WriteLn(Format('Model: %d hard-rule decisions without it, %d requests to it for %d clients, %d REVIEW, ' +
    '%.1f s wall clock', [Stats.HardRules, Stats.DeciderCalls, Stats.DeciderClients, Stats.Reviews,
    (Now - FEvalStart) * 86400]));

  if AJsonFile = '' then
    Exit;
  LRoot := TJSONObject.Create;
  LText := TStringList.Create;
  try
    LRoot.Add('decider', Describe);
    LRoot.Add('shadow', FCfg.Shadow);
    LRoot.Add('lines', Stats.Lines);
    LRoot.Add('requests', TJSONObject.Create(['rules', ConfJson(FEvalRules), 'live', ConfJson(FEvalLive)]));
    LRoot.Add('after_ban', TJSONObject.Create(['attack', FEvalAfterBan[CTruthAttack],
      'benign', FEvalAfterBan[CTruthBenign]]));
    LRoot.Add('clients', TJSONObject.Create(['attack', LAttack, 'attack_banned', LAttackBanned,
      'benign', LBenign, 'benign_banned', LBenignBanned, 'leaked_attack_requests', LLeaked,
      'leaked_per_banned_attacker_median', Median(LLeakedEach), 'seconds_to_ban_median', Median(LSecs)]));
    LCats := TJSONObject.Create;
    for I := 0 to FEvalCats.Count - 1 do
    begin
      LCat := TEvalCategory(FEvalCats.Objects[I]);
      LCatClients := 0;
      LCatBanned := 0;
      for J := 0 to FEvalClients.Count - 1 do
        if TEvalClient(FEvalClients.Objects[J]).Category = FEvalCats[I] then
        begin
          Inc(LCatClients);
          Inc(LCatBanned, Ord(TEvalClient(FEvalClients.Objects[J]).BannedAt > 0));
        end;
      LObj := TJSONObject.Create(['clients', LCatClients, 'banned', LCatBanned,
        'rules', ConfJson(LCat.Rules), 'live', ConfJson(LCat.Live)]);
      LCats.Add(FEvalCats[I], LObj);
    end;
    LRoot.Add('categories', LCats);
    LRoot.Add('model', TJSONObject.Create(['hard_rule_decisions', Stats.HardRules, 'requests', Stats.DeciderCalls,
      'clients', Stats.DeciderClients, 'errors', Stats.DeciderErrors, 'reviews', Stats.Reviews,
      'wall_seconds', (Now - FEvalStart) * 86400]));
    LText.Text := LRoot.FormatJSON;
    LText.SaveToFile(AJsonFile);
  finally
    LText.Free;
    LRoot.Free;
  end;
end;

procedure TBanEngine.FlushAll;
begin
  if FQueue.Count > 0 then
    Flush(FLastNow);
end;

procedure TBanEngine.AddStrike(C: TClient; ANow: Int64; AInstant: Boolean; const AReason: string);
var
  I, J: Integer;
begin
  Inc(Stats.Strikes);
  J := 0;
  for I := 0 to High(C.Strikes) do
    if ANow - C.Strikes[I] < FCfg.FindTime then
    begin
      C.Strikes[J] := C.Strikes[I];
      Inc(J);
    end;
  SetLength(C.Strikes, J + 1);
  C.Strikes[J] := ANow;
  if AInstant or (Length(C.Strikes) >= FCfg.MaxRetry) then
    BanClient(C, AReason);
end;

procedure TBanEngine.BanClient(C: TClient; const AReason: string);
var
  I: Integer;
  B: TBanRecord;
  LSecs, LNow: Int64;
begin
  I := FBans.IndexOf(C.IpText);
  if I >= 0 then
    B := TBanRecord(FBans.Objects[I])
  else
  begin
    B := TBanRecord.Create;
    B.Ip := C.Ip;
    B.IpText := C.IpText;
    FBans.AddObject(C.IpText, B);
  end;
  if B.Active then
    Exit;
  LSecs := FCfg.BanTime;
  if FCfg.BanIncrement and (B.Count > 0) then
    LSecs := Min(FCfg.BanMax, Round(FCfg.BanTime * Power(2, Min(B.Count, 30))));
  LNow := UnixNow;
  Inc(B.Count);
  B.Active := True;
  B.Since := LNow;
  B.Expires := LNow + LSecs;
  B.Reason := AReason;
  SetLength(C.Strikes, 0);
  Inc(Stats.Bans);
  I := FEvalClients.IndexOf(B.IpText);
  if (I >= 0) and (TEvalClient(FEvalClients.Objects[I]).BannedAt = 0) then
    TEvalClient(FEvalClients.Objects[I]).BannedAt := Max(FLastNow, 1);
  { "Ban <ip>" is what a fail2ban filter on our logfile would match }
  Log(Format('Ban %s for %ds (ban #%d): %s', [B.IpText, LSecs, B.Count, AReason]));
  if not FCfg.TestMode then
  begin
    FAction.Ban(B.Ip, LSecs);
    FDirty := True;
    SaveState;
  end;
end;

procedure TBanEngine.Purge(ANow: Int64);
var
  I: Integer;
  C: TClient;
  B: TBanRecord;
  LIdle: Int64;
begin
  LIdle := Max(FCfg.FindTime, FCfg.CacheSecs);
  for I := FClients.Count - 1 downto 0 do
  begin
    C := TClient(FClients.Objects[I]);
    if (ANow - C.LastSeen > LIdle) and not C.Queued and not C.InFlight then
      FClients.Delete(I);
  end;
  { an expired ban is remembered for bantime.increment until maxtime passes }
  for I := FBans.Count - 1 downto 0 do
  begin
    B := TBanRecord(FBans.Objects[I]);
    if not B.Active and (ANow - B.Expires > FCfg.BanMax) then
    begin
      FBans.Delete(I);
      FDirty := True;
    end;
  end;
  FLastPurge := ANow;
end;

procedure TBanEngine.Tick;
var
  I: Integer;
  B: TBanRecord;
  LNow: Int64;
begin
  if FCfg.TestMode then
    Exit;
  LNow := UnixNow;
  CollectResults;
  MaybeFlush(LNow);
  for I := 0 to FBans.Count - 1 do
  begin
    B := TBanRecord(FBans.Objects[I]);
    if B.Active and (B.Expires <= LNow) then
    begin
      B.Active := False;
      Inc(Stats.Unbans);
      Log(Format('Unban %s', [B.IpText]));
      FAction.Unban(B.Ip);
      FDirty := True;
    end;
  end;
  if LNow - FLastPurge >= 60 then
    Purge(LNow);
  if FDirty then
    SaveState;
end;

procedure TBanEngine.LoadState;
var
  LData: TJSONData;
  LArr: TJSONArray;
  LObj: TJSONObject;
  LText: TStringList;
  B: TBanRecord;
  LIp: TIpAddr;
  I: Integer;
begin
  if not FileExists(FCfg.StateFile) then
    Exit;
  LText := TStringList.Create;
  try
    LText.LoadFromFile(FCfg.StateFile);
    try
      LData := GetJSON(LText.Text);
    except
      on E: Exception do
      begin
        Log(Format('state file %s unreadable (%s); starting with no bans', [FCfg.StateFile, E.Message]));
        Exit;
      end;
    end;
  finally
    LText.Free;
  end;
  try
    if not (LData is TJSONObject) or not TJSONObject(LData).Find('bans', LArr) then
      Exit;
    for I := 0 to LArr.Count - 1 do
    begin
      if not (LArr[I] is TJSONObject) then
        Continue;
      LObj := TJSONObject(LArr[I]);
      if not ParseIp(LObj.Get('ip', ''), LIp) or (FBans.IndexOf(IpToStr(LIp)) >= 0) then
        Continue;
      B := TBanRecord.Create;
      B.Ip := LIp;
      B.IpText := IpToStr(LIp);
      B.Since := LObj.Get('since', Int64(0));
      B.Expires := LObj.Get('expires', Int64(0));
      B.Count := LObj.Get('count', 1);
      B.Active := LObj.Get('active', False);
      B.Reason := LObj.Get('reason', '');
      FBans.AddObject(B.IpText, B);
    end;
  finally
    LData.Free;
  end;
end;

procedure TBanEngine.SaveState;
var
  LRoot, LObj: TJSONObject;
  LArr: TJSONArray;
  B: TBanRecord;
  I: Integer;
  LText: TStringList;
  LTmp: string;
begin
  if FCfg.TestMode then
    Exit;
  LRoot := TJSONObject.Create;
  LText := TStringList.Create;
  try
    LRoot.Add('version', 1);
    LArr := TJSONArray.Create;
    for I := 0 to FBans.Count - 1 do
    begin
      B := TBanRecord(FBans.Objects[I]);
      LObj := TJSONObject.Create;
      LObj.Add('ip', B.IpText);
      LObj.Add('since', B.Since);
      LObj.Add('expires', B.Expires);
      LObj.Add('count', B.Count);
      LObj.Add('active', B.Active);
      LObj.Add('reason', B.Reason);
      LArr.Add(LObj);
    end;
    LRoot.Add('bans', LArr);
    LText.Text := LRoot.FormatJSON;
    try
      ForceDirectories(ExtractFileDir(ExpandFileName(FCfg.StateFile)));
      LTmp := FCfg.StateFile + '.tmp';
      LText.SaveToFile(LTmp);
      if not RenameFile(LTmp, FCfg.StateFile) then
      begin
        DeleteFile(FCfg.StateFile);
        RenameFile(LTmp, FCfg.StateFile);
      end;
      FDirty := False;
    except
      on E: Exception do
        Log(Format('could not save %s: %s', [FCfg.StateFile, E.Message]));
    end;
  finally
    LText.Free;
    LRoot.Free;
  end;
end;

procedure TBanEngine.Start;
var
  I, LRestored: Integer;
  B: TBanRecord;
  LNow: Int64;
begin
  LoadState;
  FAction.Start;
  LNow := UnixNow;
  LRestored := 0;
  for I := 0 to FBans.Count - 1 do
  begin
    B := TBanRecord(FBans.Objects[I]);
    if not B.Active then
      Continue;
    if B.Expires > LNow then
    begin
      FAction.Ban(B.Ip, B.Expires - LNow);
      Inc(LRestored);
    end
    else
    begin
      B.Active := False;
      FDirty := True;
      { a chain-based action was just flushed by actionstart; others keep
        their rules across our restart and need the unban }
      if FAction.StartCmd = '' then
        FAction.Unban(B.Ip);
      Log(Format('Unban %s (expired while stopped)', [B.IpText]));
    end;
  end;
  if LRestored > 0 then
    Log(Format('restored %d ban(s) from %s', [LRestored, FCfg.StateFile]));
  FLastPurge := LNow;
  if FDirty then
    SaveState;
end;

procedure TBanEngine.Stop;
begin
  if FWorker <> nil then
  begin
    { a batch in progress stops between clients; what is still queued is dropped }
    DeciderAbort := True;
    FreeAndNil(FWorker);
  end
  else
    FlushAll;
  SaveState;
  if FCfg.CleanupOnExit then
    FAction.Stop;
end;

procedure TBanEngine.PrintBans;
var
  I, LActive: Integer;
  B: TBanRecord;
  LNow: Int64;
begin
  LoadState;
  LNow := UnixNow;
  LActive := 0;
  for I := 0 to FBans.Count - 1 do
  begin
    B := TBanRecord(FBans.Objects[I]);
    if not B.Active or (B.Expires <= LNow) then
      Continue;
    Inc(LActive);
    WriteLn(Format('%-39s %7ds left  ban #%d  %s', [B.IpText, B.Expires - LNow, B.Count, B.Reason]));
  end;
  WriteLn(Format('%d active ban(s), %d remembered for bantime.increment, state %s',
    [LActive, FBans.Count - LActive, FCfg.StateFile]));
end;

function TBanEngine.Summary: string;
begin
  Result := Format('%d lines, %d parsed, %d ignored, %d suspicious, %d by hard rules, %d decider ' +
    'requests for %d clients (%d failed), %d review, %d strikes, %d bans, %d unbans', [Stats.Lines,
    Stats.Parsed, Stats.Ignored, Stats.Suspicious, Stats.HardRules, Stats.DeciderCalls, Stats.DeciderClients,
    Stats.DeciderErrors, Stats.Reviews, Stats.Strikes, Stats.Bans, Stats.Unbans]);
end;

end.
