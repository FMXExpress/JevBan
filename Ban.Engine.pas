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
   rules decide. Bans survive a restart in the state file. *)

{$mode objfpc}{$H+}

interface

uses
  SysUtils, Classes, Math, fpjson, jsonparser,
  Ban.Net, Ban.Apache, Ban.Signatures, Ban.Jev, Ban.Local, Ban.Firewall, Ban.Config;

type
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
    Pending: TStringList;    { flagged requests waiting for the batch; Objects = score }
    PendingTags: TStringList;    { all tags of the pending requests (sent to the decider) }
    PendingLineTags: TStringList;  { per pending request, for the log }
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
    Lines, Parsed, Ignored, Suspicious, DeciderCalls, DeciderClients, DeciderErrors, Strikes, Bans,
      Unbans: Int64;
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
    function GetClient(const E: TAccessEntry; ANow: Int64): TClient;
    procedure Judge(C: TClient; const ASummary: string; AScore: Integer; ATags: TStrings; ANow: Int64);
    procedure ApplyVerdict(C: TClient; AMal: Double; const AIntent: string; AScore: Integer;
      const ATags, ASummary, AHow: string; ANow: Int64);
    procedure ApplyRules(C: TClient; AScore: Integer; const ATags, ASummary, AHow: string; ANow: Int64);
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
    procedure Feed(const ALine: string);
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
  Pending := TStringList.Create;
  PendingTags := TStringList.Create;
  PendingLineTags := TStringList.Create;
end;

destructor TClient.Destroy;
begin
  PendingLineTags.Free;
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

procedure TBanEngine.Feed(const ALine: string);
var
  E: TAccessEntry;
  C: TClient;
  LNow: Int64;
  LTags: TStringList;
  LScore, I: Integer;
  LSummary: string;
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
  FLastNow := LNow;
  if FQueue.Count > 0 then
    Inc(FLinesSinceFlush);
  I := FBans.IndexOf(E.IpText);
  if (I >= 0) and TBanRecord(FBans.Objects[I]).Active then
    Exit;   { already banned: a connection that was open before the ban }
  C := GetClient(E, LNow);
  C.LastSeen := LNow;
  LSummary := EntrySummary(E);
  LTags := TStringList.Create;
  try
    LTags.Duplicates := dupIgnore;
    LScore := FSigs.Score(E, LTags);
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
      Judge(C, LSummary, LScore, LTags, LNow);
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

procedure TBanEngine.Judge(C: TClient; const ASummary: string; AScore: Integer; ATags: TStrings;
  ANow: Int64);
var
  LTag: string;
begin
  if FDecider = nil then
  begin
    ApplyRules(C, AScore, ATags.CommaText, ASummary, 'rules', ANow);
    Exit;
  end;
  if (C.VerdictAt > 0) and (ANow - C.VerdictAt < FCfg.CacheSecs) and not C.Queued then
  begin
    ApplyVerdict(C, C.VerdictMal, C.VerdictIntent, AScore, ATags.CommaText, ASummary, FCfg.Mode + ' (cached)', ANow);
    Exit;
  end;
  { the next batch decides }
  if not C.Queued then
  begin
    C.Queued := True;
    C.PendingSince := ANow;
    FQueue.Add(C);
  end;
  if C.Pending.Count < 2 * FCfg.ContextLines then
  begin
    C.Pending.AddObject(ASummary, TObject(PtrInt(AScore)));
    C.PendingLineTags.Add(ATags.CommaText);
  end;
  for LTag in ATags do
    if C.PendingTags.IndexOf(LTag) < 0 then
      C.PendingTags.Add(LTag);
  if FCfg.Verbose then
    Log(Format('%s queued (%d in batch) score=%d [%s]: %s', [C.IpText, FQueue.Count, AScore,
      ATags.CommaText, Copy(ASummary, 1, 300)]));
end;

procedure TBanEngine.ApplyVerdict(C: TClient; AMal: Double; const AIntent: string; AScore: Integer;
  const ATags, ASummary, AHow: string; ANow: Int64);
var
  LStrike, LInstant: Boolean;
  LHow, LVerdict: string;
begin
  LHow := AHow;
  LStrike := AMal >= FCfg.Threshold;
  LInstant := AMal >= FCfg.InstantThreshold;
  if (FCfg.OverrideScore > 0) and (AScore >= FCfg.OverrideScore) and not LStrike then
  begin
    LStrike := True;
    LHow := LHow + ', score override';
  end;
  if LInstant then
    LVerdict := 'BAN'
  else if LStrike then
    LVerdict := Format('strike %d/%d', [Length(C.Strikes) + 1, FCfg.MaxRetry])
  else
    LVerdict := 'pass';
  if FCfg.Verbose or FCfg.TestMode or LStrike then
    Log(Format('%s %s score=%d [%s] p=%.2f%s via %s: %s', [C.IpText, LVerdict, AScore, ATags, AMal,
      BoolToStr(AIntent <> '', ' intent=' + AIntent, ''), LHow, Copy(ASummary, 1, 300)]));
  if LStrike then
    AddStrike(C, ANow, LInstant, Format('%s, p=%.2f%s', [ATags, AMal,
      BoolToStr(AIntent <> '', ' ' + AIntent, '')]));
end;

procedure TBanEngine.ApplyRules(C: TClient; AScore: Integer; const ATags, ASummary, AHow: string;
  ANow: Int64);
var
  LStrike, LInstant: Boolean;
  LVerdict: string;
begin
  LStrike := AScore >= FCfg.RulesMinScore;
  LInstant := AScore >= FCfg.RulesInstantScore;
  if LInstant then
    LVerdict := 'BAN'
  else if LStrike then
    LVerdict := Format('strike %d/%d', [Length(C.Strikes) + 1, FCfg.MaxRetry])
  else
    LVerdict := 'pass';
  if FCfg.Verbose or FCfg.TestMode or LStrike then
    Log(Format('%s %s score=%d [%s] via %s: %s', [C.IpText, LVerdict, AScore, ATags, AHow,
      Copy(ASummary, 1, 300)]));
  if LStrike then
    AddStrike(C, ANow, LInstant, Format('%s, score %d', [ATags, AScore]));
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
        LItem.Flagged.Assign(C.Pending);
        for J := 0 to C.Recent.Count - 1 do
          if C.Pending.IndexOf(C.Recent[J]) < 0 then
            LItem.Earlier.Add(C.Recent[J]);
        LItems.Add(LItem);
      end;

      if ANow div 60 <> FMinute then
      begin
        FMinute := ANow div 60;
        FMinuteCalls := 0;
      end;
      LOk := False;
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
          if IsBanned(C.IpText) then
            Break;
          if LOk then
            ApplyVerdict(C, LItem.Malicious, LItem.Intent, PtrInt(C.Pending.Objects[J]),
              C.PendingLineTags[J], C.Pending[J], LHow, ANow)
          else if (LError = 'rate limit') or (FCfg.OnError = 'rules') then
            ApplyRules(C, PtrInt(C.Pending.Objects[J]), C.PendingLineTags[J], C.Pending[J], LHow, ANow)
          else if FCfg.Verbose or FCfg.TestMode then
            Log(Format('%s pass [%s] via %s: %s', [C.IpText, C.PendingLineTags[J], LHow,
              Copy(C.Pending[J], 1, 300)]));
        end;
        C.Pending.Clear;
        C.PendingTags.Clear;
        C.PendingLineTags.Clear;
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
  Result := Format('%d lines, %d parsed, %d ignored, %d suspicious, %d decider requests for %d ' +
    'clients (%d failed), %d strikes, %d bans, %d unbans', [Stats.Lines, Stats.Parsed, Stats.Ignored,
    Stats.Suspicious, Stats.DeciderCalls, Stats.DeciderClients, Stats.DeciderErrors, Stats.Strikes,
    Stats.Bans, Stats.Unbans]);
end;

end.
