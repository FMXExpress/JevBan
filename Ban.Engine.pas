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
   log and counts both against the labels. *)

{$mode objfpc}{$H+}

interface

uses
  SysUtils, Classes, Math, Contnrs, fpjson, jsonparser,
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
  end;

  { true/false positives and negatives of strike decisions, per request }
  TConfusion = record
    TP, FP, FN, TN: Int64;
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
    { --eval: strike decisions per labelled request, rules alone and the whole pipeline }
    FEvalRules, FEvalLive: TConfusion;
    FEvalAfterBan: array[CTruthBenign..CTruthAttack] of Int64;
    FEvalClients: TStringList;   { ip -> Objects: 1 = sent an attack, 2 = sent benign requests }
    procedure Count(var AConf: TConfusion; ATruth: Integer; AStrike: Boolean);
    function GetClient(const E: TAccessEntry; ANow: Int64): TClient;
    procedure Judge(C: TClient; const ASummary, ATags: string; AScore, ATruth: Integer; ANow: Int64);
    { the one place a flagged request is decided. AMal < 0: no model verdict
      (rules mode, a hard rule, the decider unavailable) }
    procedure Decide(C: TClient; const ASummary, ATags: string; AScore, ATruth: Integer; AMal: Double;
      const AIntent, AHow: string; ANow: Int64);
    function IsBanned(const AIp: string): Boolean;
    procedure MaybeFlush(ANow: Int64);
    procedure Flush(ANow: Int64);
    procedure AddStrike(C: TClient; ANow: Int64; AInstant: Boolean; const AReason: string);
    procedure BanClient(C: TClient; const AReason: string);
    procedure Purge(ANow: Int64);
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
    procedure Feed(const ALine: string; ATruth: Integer = CTruthUnknown);
    { --eval: the counts against the labels }
    procedure EvalReport;
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
  FLog.Free;
  FEvalClients.Free;
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

function TBanEngine.GetClient(const E: TAccessEntry; ANow: Int64): TClient;
var
  I, LOldest: Integer;
begin
  I := FClients.IndexOf(E.IpText);
  if I >= 0 then
    Exit(TClient(FClients.Objects[I]));
  if FClients.Count >= FCfg.MaxClients then
  begin
    Purge(ANow);
    if FClients.Count >= FCfg.MaxClients then
    begin
      { still full: drop the client seen longest ago }
      LOldest := -1;
      for I := 0 to FClients.Count - 1 do
        if not TClient(FClients.Objects[I]).Queued and ((LOldest < 0) or
           (TClient(FClients.Objects[I]).LastSeen < TClient(FClients.Objects[LOldest]).LastSeen)) then
          LOldest := I;
      if LOldest >= 0 then
        FClients.Delete(LOldest);
    end;
  end;
  Result := TClient.Create;
  Result.IpText := E.IpText;
  Result.Ip := E.Ip;
  FClients.AddObject(E.IpText, Result);
end;

procedure TBanEngine.Feed(const ALine: string; ATruth: Integer);
var
  E: TAccessEntry;
  C: TClient;
  LNow: Int64;
  LTags: TStringList;
  LScore, I, LDist: Integer;
  LSummary, LPath, LNear: string;
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
  if ATruth <> CTruthUnknown then
  begin
    I := FEvalClients.IndexOf(E.IpText);
    if I < 0 then
      I := FEvalClients.AddObject(E.IpText, nil);
    FEvalClients.Objects[I] := TObject(PtrInt(FEvalClients.Objects[I]) or IfThen(ATruth = CTruthAttack, 1, 2));
  end;
  { replaying a file (--test) runs on the log's clock, live on the wall clock }
  if FCfg.TestMode and (E.Epoch > 0) then
    LNow := E.Epoch
  else
    LNow := UnixNow;
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
        else
        begin
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
      Judge(C, LSummary, LTags.CommaText, LScore, ATruth, LNow);
    end
    else if ATruth <> CTruthUnknown then
    begin
      { not flagged: neither rules nor model strike }
      Count(FEvalRules, ATruth, False);
      Count(FEvalLive, ATruth, False);
    end;
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

procedure TBanEngine.Judge(C: TClient; const ASummary, ATags: string; AScore, ATruth: Integer; ANow: Int64);
var
  LLine: TPendingLine;
  LTag: string;
  LTagList: TStringList;
begin
  if FDecider = nil then
  begin
    Decide(C, ASummary, ATags, AScore, ATruth, -1, '', 'rules', ANow);
    Exit;
  end;
  { the model never overrides a hard rule, and is not asked about one }
  if (FCfg.OverrideScore > 0) and (AScore >= FCfg.OverrideScore) then
  begin
    Inc(Stats.HardRules);
    Decide(C, ASummary, ATags, AScore, ATruth, -1, '', 'hard rule', ANow);
    Exit;
  end;
  if (C.VerdictAt > 0) and (ANow - C.VerdictAt < FCfg.CacheSecs) and not C.Queued then
  begin
    Decide(C, ASummary, ATags, AScore, ATruth, C.VerdictMal, C.VerdictIntent, FCfg.Mode + ' (cached)', ANow);
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

procedure TBanEngine.Decide(C: TClient; const ASummary, ATags: string; AScore, ATruth: Integer; AMal: Double;
  const AIntent, AHow: string; ANow: Int64);
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
  Count(FEvalRules, ATruth, LRulesStrike);
  Count(FEvalLive, ATruth, LStrike);

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
  LClients, LItems: TList;
  LItem: TJevItem;
  LLine: TPendingLine;
  C: TClient;
  I, J: Integer;
  LOk: Boolean;
  LError, LHow: string;
  LMs: Int64;
begin
  LClients := TList.Create;
  LItems := TList.Create;
  try
    while FQueue.Count > 0 do
    begin
      LClients.Clear;
      for I := LItems.Count - 1 downto 0 do
        TJevItem(LItems[I]).Free;
      LItems.Clear;
      while (FQueue.Count > 0) and (LClients.Count < FCfg.BatchClients) do
      begin
        C := TClient(FQueue[0]);
        FQueue.Delete(0);
        LClients.Add(C);
        LItem := TJevItem.Create;
        LItem.Ip := C.IpText;
        LItem.Hits := C.PendingTags.CommaText;
        { the model sees the latest flagged requests; all of them get its verdict }
        for J := Max(0, C.Pending.Count - 2 * FCfg.ContextLines) to C.Pending.Count - 1 do
          LItem.Flagged.Add(TPendingLine(C.Pending[J]).Summary);
        for J := 0 to C.Recent.Count - 1 do
          if LItem.Flagged.IndexOf(C.Recent[J]) < 0 then
            LItem.Earlier.Add(C.Recent[J]);
        LItems.Add(LItem);
      end;

      if ANow div 60 <> FMinute then
      begin
        FMinute := ANow div 60;
        FMinuteCalls := 0;
      end;
      LOk := False;
      LError := '';
      if FMinuteCalls >= FCfg.MaxPerMinute then
      begin
        LError := 'rate limit';
        LHow := 'rules (decider rate limit)';
      end
      else
      begin
        Inc(FMinuteCalls);
        Inc(Stats.DeciderCalls);
        Inc(Stats.DeciderClients, LItems.Count);
        LOk := FDecider.Decide(LItems, LError, LMs);
        if LOk then
          LHow := Format('%s batch of %d, %dms', [FCfg.Mode, LItems.Count, LMs])
        else
        begin
          Inc(Stats.DeciderErrors);
          Inc(FErrsSinceLog);
          if UnixNow - FLastErrLog >= 60 then
          begin
            Log(Format('decider error (%d since last report): %s', [FErrsSinceLog, LError]));
            FLastErrLog := UnixNow;
            FErrsSinceLog := 0;
          end;
          if FCfg.OnError = 'rules' then
            LHow := 'rules (decider unavailable)'
          else
            LHow := 'skipped (decider unavailable)';
        end;
      end;

      for I := 0 to LClients.Count - 1 do
      begin
        C := TClient(LClients[I]);
        LItem := TJevItem(LItems[I]);
        if LOk then
        begin
          C.VerdictAt := ANow;
          C.VerdictMal := LItem.Malicious;
          C.VerdictIntent := LItem.Intent;
        end;
        for J := 0 to C.Pending.Count - 1 do
        begin
          LLine := TPendingLine(C.Pending[J]);
          if IsBanned(C.IpText) then
          begin
            if LLine.Truth <> CTruthUnknown then
              Inc(FEvalAfterBan[LLine.Truth]);
            Continue;
          end;
          if LOk then
            Decide(C, LLine.Summary, LLine.Tags, LLine.Score, LLine.Truth, LItem.Malicious, LItem.Intent,
              LHow, ANow)
          else if (LError = 'rate limit') or (FCfg.OnError = 'rules') then
            Decide(C, LLine.Summary, LLine.Tags, LLine.Score, LLine.Truth, -1, '', LHow, ANow)
          else
          begin
            Count(FEvalRules, LLine.Truth, LLine.Score >= FCfg.RulesMinScore);
            Count(FEvalLive, LLine.Truth, False);
            if FCfg.Verbose or FCfg.TestMode then
              Log(Format('%s pass [%s] via %s: %s', [C.IpText, LLine.Tags, LHow, Copy(LLine.Summary, 1, 300)]));
          end;
        end;
        C.Pending.Clear;
        C.PendingTags.Clear;
        C.Queued := False;
      end;
    end;
  finally
    for I := 0 to LItems.Count - 1 do
      TJevItem(LItems[I]).Free;
    LItems.Free;
    LClients.Free;
  end;
  FLinesSinceFlush := 0;
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
end;

function TBanEngine.Describe: string;
begin
  if FDecider <> nil then
    Result := FDecider.Describe
  else
    Result := 'rules';
end;

procedure TBanEngine.EvalReport;

  function Pct(A, B: Int64): string;
  begin
    if B = 0 then
      Result := '   -  '
    else
      Result := Format('%5.1f%%', [100 * A / B]);
  end;

  procedure Row(const AName: string; const C: TConfusion);
  begin
    WriteLn(Format('  %-22s %5d %5d %5d %5d   %s   %s', [AName, C.TP, C.FP, C.FN, C.TN,
      Pct(C.TP, C.TP + C.FP), Pct(C.TP, C.TP + C.FN)]));
  end;

var
  I, LAttack, LBenign, LAttackBanned, LBenignBanned: Integer;
  LBanned: Boolean;
  LFlags: PtrInt;
begin
  WriteLn;
  WriteLn('Strike decisions per labelled request (attack = positive):');
  WriteLn('                            TP    FP    FN    TN   precision  recall');
  Row('signatures only', FEvalRules);
  if FDecider <> nil then
    Row(BoolToStr(FCfg.Shadow, 'live (shadow: rules)', 'live (hard rules+model)'), FEvalLive)
  else
    Row('live (rules)', FEvalLive);
  WriteLn(Format('  requests after the client was banned: %d attack (stopped), %d benign (lost)',
    [FEvalAfterBan[CTruthAttack], FEvalAfterBan[CTruthBenign]]));
  LAttack := 0;
  LBenign := 0;
  LAttackBanned := 0;
  LBenignBanned := 0;
  for I := 0 to FEvalClients.Count - 1 do
  begin
    LFlags := PtrInt(FEvalClients.Objects[I]);
    LBanned := FBans.IndexOf(FEvalClients[I]) >= 0;
    if LFlags and 1 <> 0 then
    begin
      Inc(LAttack);
      Inc(LAttackBanned, Ord(LBanned));
    end
    else
    begin
      Inc(LBenign);
      Inc(LBenignBanned, Ord(LBanned));
    end;
  end;
  WriteLn(Format('Clients: %d of %d attackers banned; %d of %d benign clients banned (false bans)',
    [LAttackBanned, LAttack, LBenignBanned, LBenign]));
  WriteLn(Format('Model: %d hard-rule decisions without it, %d requests to it for %d clients, %d REVIEW',
    [Stats.HardRules, Stats.DeciderCalls, Stats.DeciderClients, Stats.Reviews]));
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
    if (ANow - C.LastSeen > LIdle) and not C.Queued then
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
