unit Ban.Config;

(* jevban.ini, then the command line on top. The keys follow fail2ban's
   names where there is one (logpath, ignoreip, findtime, maxretry, bantime,
   bantime.increment, actionban, ...). Lookup order for the file: --config,
   /etc/jevban/jevban.ini, jevban.ini next to the executable; none at all is
   fine (the defaults below). *)

{$mode objfpc}{$H+}

interface

uses
  SysUtils, Classes, Math, IniFiles, {$IFDEF UNIX}BaseUnix,{$ENDIF} Ban.Net;

type
  TBanConfig = class
  public
    ConfigFile: string;
    { [jevban] }
    LogPaths: TStringList;
    FromStart: Boolean;
    PollMs: Integer;
    StateFile: string;
    LogFile: string;
    IgnoreIp: TCidrList;
    IgnoreIpText: string;
    FindTime: Int64;
    MaxRetry: Integer;
    BanTime: Int64;
    BanIncrement: Boolean;    { each repeat ban lasts twice as long ... }
    BanMax: Int64;            { ... up to this }
    ContextLines: Integer;    { recent requests per client kept for the model }
    MaxClients: Integer;
    Flood4xx: Integer;        { this many 4xx in findtime is suspicious too; 0 = off }
    SignatureFile: string;
    BuiltinSignatures: Boolean;
    SuspiciousScore: Integer; { prefilter score that sends a request to the decider }
    Verbose: Boolean;
    Nice: Integer;            { the daemon's scheduling niceness (Unix), below-normal priority on Windows if > 0 }
    { [decider] }
    Mode: string;             { local (OpenJev in-process) | jev (a /v1/systemone server) | rules }
    LocalModel: string;       { flash-9b, flash-9b-q8, 27b, ... or a .gguf path }
    ModelDir: string;
    LlamaLibDir: string;
    Threads: Integer;
    GpuLayers: Integer;
    CtxTokens: Integer;
    ReadoutT, NoulT, NoulBias: Double;   { 0 = the model card's values (NoulBias: NaN) }
    Provider: string;         { a hosted /v1/systemone service (CProviders), or '' }
    JevUrl: string;
    JevKey: string;
    JevModel: string;
    TimeoutMs: Integer;
    Threshold: Double;        { P(malicious) that counts as a strike }
    InstantThreshold: Double; { P(malicious) that bans at once }
    CacheSecs: Integer;       { reuse a client's verdict this long }
    CachePassSecs: Integer;   { ... and a pass this long, while the client does nothing new }
    BatchInterval: Integer;   { flush the queue of flagged clients after this many seconds ... }
    BatchLines: Integer;      { ... or this many log lines ... }
    BatchClients: Integer;    { ... or when this many clients are queued (one request each flush) }
    AskIntent: Boolean;       { also ask what each client is doing (a second readout per client) }
    MaxPerMinute: Integer;    { decider calls; beyond it, rules decide }
    OnError: string;          { rules | skip }
    RulesMinScore: Integer;   { rules: a strike }
    RulesInstantScore: Integer;
    OverrideScore: Integer;   { a score this high is a strike without asking the model; 0 = off }
    ReviewThreshold: Double;  { a p from here up to threshold is logged as REVIEW; 0 = off }
    Shadow: Boolean;          { the model's verdicts are logged only; the rules ban }
    BadPathsFile: string;     { known-bad paths ('' = off) }
    Site: string;
    Question: string;
    { [action] }
    ActionType: string;
    ActionName: string;
    Port: string;
    Jail: string;
    ActionStart, ActionStop, ActionBan, ActionUnban: string;
    DryRun: Boolean;
    CleanupOnExit: Boolean;
    { command line only }
    TestMode: Boolean;
    EvalMode: Boolean;        { --eval: TestMode on a labelled log }
    EvalJson: string;         { --eval-json: the eval counts as JSON too }
    ListBans: Boolean;
    constructor Create;
    destructor Destroy; override;
    { fills url, model and the key from Provider where the config left them unset }
    procedure ApplyProvider(AUrlSet, AModelSet: Boolean);
    { parses the command line; raises EArgumentException on a bad option.
      Returns False when --help/--version printed and the program should exit }
    function Load: Boolean;
    procedure Validate;
  end;

procedure PrintUsage;
function ProviderNames: string;

type
  TProviderInfo = record
    Name: string;
    Url: string;
    Model: string;
    KeyEnv: string;          { the variable the provider's docs use for the key }
    MaxQuestions: Integer;   { per request; 0 = no stated limit }
    MaxPerMinute: Integer;   { requests; 0 = no stated limit }
  end;

const
  CVersion = '1.0.0';
  { from each provider's own documentation (October 2026); all take the Jev request
    body and Authorization: Bearer <key> }
  CProviders: array[0..6] of TProviderInfo = (
    (Name: 'typesafe'; Url: 'https://api.typesafe.ai/v1/systemone'; Model: 'jev-latest';
      KeyEnv: 'TYPESAFE_API_KEY'; MaxQuestions: 0; MaxPerMinute: 0),
    (Name: 'perplexity'; Url: 'https://api.perplexity.ai/v1/decisions'; Model: 'pplx-decider-latest';
      KeyEnv: 'PERPLEXITY_API_KEY'; MaxQuestions: 0; MaxPerMinute: 0),
    (Name: 'perplexity-flash'; Url: 'https://api.perplexity.ai/v1/decisions'; Model: 'pplx-decider-flash-latest';
      KeyEnv: 'PERPLEXITY_API_KEY'; MaxQuestions: 0; MaxPerMinute: 0),
    (Name: 'liquid'; Url: 'https://api.liquid.ai/decisions/v1/systemone'; Model: 'd1.1';
      KeyEnv: 'LIQUID_API_KEY'; MaxQuestions: 0; MaxPerMinute: 0),
    (Name: 'digitalocean'; Url: 'https://inference.do-ai.run/v1/systemone'; Model: 'typesafe-jev-1.13.0';
      KeyEnv: 'MODEL_ACCESS_KEY'; MaxQuestions: 0; MaxPerMinute: 0),
    (Name: 'abacus'; Url: 'https://routellm.abacus.ai/v1/systemone'; Model: 'jev-latest';
      KeyEnv: 'ABACUS_API_KEY'; MaxQuestions: 10; MaxPerMinute: 20),
    (Name: 'vercel'; Url: 'https://ai-gateway.vercel.sh/typesafe/v1/systemone'; Model: 'typesafe-ai/jev';
      KeyEnv: 'AI_GATEWAY_API_KEY'; MaxQuestions: 0; MaxPerMinute: 0));

implementation

uses
  Ban.Jev;

function ProviderNames: string;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to High(CProviders) do
  begin
    if Result <> '' then
      Result := Result + ', ';
    Result := Result + CProviders[I].Name;
  end;
end;

procedure PrintUsage;
begin
  WriteLn('jevban ', CVersion, ' - ban web attackers found in Apache logs, decided by a Jev-style AI');
  WriteLn;
  WriteLn('usage: jevban [options]');
  WriteLn('  -c, --config FILE      settings (default /etc/jevban/jevban.ini, else next to the binary)');
  WriteLn('  -l, --log FILE         access log or wildcard pattern to follow (repeatable; replaces logpath)');
  WriteLn('      --from-start       read the logs from their start, not just new lines');
  WriteLn('  -t, --test FILE        read FILE once, print each decision, ban nothing (like fail2ban-regex)');
  WriteLn('      --eval FILE        replay a labelled log ("attack<TAB>line" / "benign<TAB>line") and count');
  WriteLn('                         the strike decisions of the signatures and of the live pipeline');
  WriteLn('      --eval-json FILE   write the --eval counts to FILE as JSON too');
  WriteLn('      --shadow           ask the model and log its verdicts, but let the signatures ban');
  WriteLn('  -n, --dry-run          log the firewall commands instead of running them');
  WriteLn('  -m, --mode MODE        local (OpenJev in-process, the default) | jev (a /v1/systemone server)');
  WriteLn('                         | rules (signatures only)');
  WriteLn('      --model NAME       local model: flash-9b (5.6 GB, default), flash-9b-q5/-q6/-q8, 27b,');
  WriteLn('                         27b-q5/-q6/-q8, or a .gguf path; downloaded on first use');
  WriteLn('  -p, --provider NAME    ask a hosted decision API (implies --mode jev; key in api_key or the');
  WriteLn('                         provider''s variable): ' + ProviderNames);
  WriteLn('  -u, --jev-url URL      ask this /v1/systemone server instead (implies --mode jev)');
  WriteLn('  -a, --action TYPE      iptables | nftables | ufw | firewalld | fail2ban | netsh | command | none');
  WriteLn('  -b, --batch SECONDS    queue flagged clients and ask the decider about them in one request');
  WriteLn('                         every SECONDS (also every batch_lines lines / batch_clients clients)');
  WriteLn('      --list             print the bans in the state file and exit');
  WriteLn('  -v, --verbose          log every request the prefilter flags, and every verdict');
  WriteLn('  -h, --help             this text');
  WriteLn('      --version');
  WriteLn;
  WriteLn('environment: JEV_API_KEY or the provider''s own (TYPESAFE_API_KEY, PERPLEXITY_API_KEY,');
  WriteLn('  LIQUID_API_KEY, MODEL_ACCESS_KEY, ABACUS_API_KEY, AI_GATEWAY_API_KEY), HTTPS_PROXY, NO_PROXY');
end;

constructor TBanConfig.Create;
begin
  inherited Create;
  LogPaths := TStringList.Create;
  {$IFDEF WINDOWS}
  StateFile := ExtractFilePath(ParamStr(0)) + 'jevban-state.json';
  {$ELSE}
  StateFile := '/var/lib/jevban/state.json';
  {$ENDIF}
  PollMs := 250;
  IgnoreIpText := '127.0.0.0/8 ::1';
  FindTime := 600;
  MaxRetry := 3;
  BanTime := 3600;
  BanIncrement := True;
  BanMax := 7 * 86400;
  ContextLines := 6;
  MaxClients := 20000;
  Flood4xx := 40;
  BuiltinSignatures := True;
  SuspiciousScore := 3;
  Nice := 10;
  Mode := 'local';
  LocalModel := 'flash-9b';
  {$IFDEF WINDOWS}
  ModelDir := ExtractFilePath(ParamStr(0)) + 'models';
  {$ELSE}
  { the uid, not $USER: systemd sets no USER for a root service }
  if FpGetUid = 0 then
    ModelDir := '/var/lib/jevban/models'
  else
    ModelDir := IncludeTrailingPathDelimiter(GetUserDir) + '.cache/jevban/models';
  {$ENDIF}
  { a release keeps the llama.cpp libraries next to the binary }
  LlamaLibDir := ExtractFilePath(ParamStr(0));
  CtxTokens := 8192;
  NoulBias := NaN;
  JevUrl := 'http://127.0.0.1:3000/v1/systemone';
  JevModel := 'openjev';
  TimeoutMs := 8000;
  Threshold := 0.80;
  InstantThreshold := 0.97;
  CacheSecs := 60;
  CachePassSecs := 1800;
  BatchInterval := 5;
  BatchLines := 1000;
  BatchClients := 8;
  MaxPerMinute := 120;
  OnError := 'rules';
  RulesMinScore := 6;
  RulesInstantScore := 20;
  OverrideScore := 10;
  ReviewThreshold := 0.5;
  BadPathsFile := ExtractFilePath(ParamStr(0)) + 'badpaths.txt';
  Site := CDefaultSite;
  Question := CDefaultQuestion;
  {$IFDEF WINDOWS}
  ActionType := 'netsh';
  {$ELSE}
  ActionType := 'iptables';
  {$ENDIF}
  ActionName := 'jevban';
  Port := '80,443';
  Jail := 'jevban';
  CleanupOnExit := True;
end;

destructor TBanConfig.Destroy;
begin
  LogPaths.Free;
  inherited Destroy;
end;

function SplitList(const S: string; ADest: TStrings): Integer;
var
  LItems: TStringList;
  LItem: string;
begin
  LItems := TStringList.Create;
  try
    LItems.StrictDelimiter := True;
    LItems.Delimiter := ',';
    LItems.DelimitedText := StringReplace(S, LineEnding, ',', [rfReplaceAll]);
    for LItem in LItems do
      if Trim(LItem) <> '' then
        ADest.Add(Trim(LItem));
  finally
    LItems.Free;
  end;
  Result := ADest.Count;
end;

function TBanConfig.Load: Boolean;
var
  I: Integer;
  LArg, LVal: string;
  LIni: TMemIniFile;
  LCliLogs: TStringList;
  LCli: TStringList;   { name=value from the command line, applied after the file }
  LUrlSet, LModelSet: Boolean;

  function NextVal: string;
  begin
    if I >= ParamCount then
      raise EArgumentException.CreateFmt('%s needs a value', [LArg]);
    Inc(I);
    Result := ParamStr(I);
  end;

  { probabilities are written 0.85 whatever the locale }
  function F(const AKey: string; ADef: Double): Double;
  var
    LFmt: TFormatSettings;
  begin
    LFmt := DefaultFormatSettings;
    LFmt.DecimalSeparator := '.';
    Result := StrToFloatDef(Trim(LIni.ReadString('decider', AKey, '')), ADef, LFmt);
  end;

begin
  Result := True;
  LCliLogs := TStringList.Create;
  LCli := TStringList.Create;
  try
    I := 1;
    while I <= ParamCount do
    begin
      LArg := ParamStr(I);
      if (LArg = '-h') or (LArg = '--help') then
      begin
        PrintUsage;
        Exit(False);
      end
      else if LArg = '--version' then
      begin
        WriteLn('jevban ', CVersion);
        Exit(False);
      end
      else if (LArg = '-c') or (LArg = '--config') then
        ConfigFile := NextVal
      else if (LArg = '-l') or (LArg = '--log') then
        LCliLogs.Add(NextVal)
      else if LArg = '--from-start' then
        LCli.Values['from_start'] := '1'
      else if (LArg = '-t') or (LArg = '--test') then
      begin
        LCliLogs.Add(NextVal);
        TestMode := True;
      end
      else if (LArg = '-n') or (LArg = '--dry-run') then
        LCli.Values['dry_run'] := '1'
      else if (LArg = '-m') or (LArg = '--mode') then
        LCli.Values['mode'] := NextVal
      else if (LArg = '-u') or (LArg = '--jev-url') then
        LCli.Values['url'] := NextVal
      else if (LArg = '-a') or (LArg = '--action') then
        LCli.Values['type'] := NextVal
      else if (LArg = '-p') or (LArg = '--provider') then
        LCli.Values['provider'] := NextVal
      else if LArg = '--model' then
        LCli.Values['local_model'] := NextVal
      else if (LArg = '-b') or (LArg = '--batch') then
        LCli.Values['batch_interval'] := NextVal
      else if LArg = '--eval' then
      begin
        LCliLogs.Add(NextVal);
        TestMode := True;
        EvalMode := True;
      end
      else if LArg = '--eval-json' then
        EvalJson := NextVal
      else if LArg = '--shadow' then
        LCli.Values['shadow'] := '1'
      else if LArg = '--list' then
        ListBans := True
      else if (LArg = '-v') or (LArg = '--verbose') then
        Verbose := True
      else
        raise EArgumentException.CreateFmt('unknown option %s (try --help)', [LArg]);
      Inc(I);
    end;

    if ConfigFile = '' then
    begin
      {$IFNDEF WINDOWS}
      if FileExists('/etc/jevban/jevban.ini') then
        ConfigFile := '/etc/jevban/jevban.ini'
      else
      {$ENDIF}
      if FileExists(ExtractFilePath(ParamStr(0)) + 'jevban.ini') then
        ConfigFile := ExtractFilePath(ParamStr(0)) + 'jevban.ini';
    end
    else if not FileExists(ConfigFile) then
      raise EArgumentException.CreateFmt('config file %s not found', [ConfigFile]);

    LIni := TMemIniFile.Create(ConfigFile);   { '' = empty, all defaults }
    try
      SplitList(LIni.ReadString('jevban', 'logpath', ''), LogPaths);
      FromStart := LIni.ReadBool('jevban', 'from_start', FromStart);
      PollMs := LIni.ReadInteger('jevban', 'poll_ms', PollMs);
      StateFile := LIni.ReadString('jevban', 'statefile', StateFile);
      LogFile := LIni.ReadString('jevban', 'logfile', LogFile);
      IgnoreIpText := LIni.ReadString('jevban', 'ignoreip', IgnoreIpText);
      FindTime := LIni.ReadInt64('jevban', 'findtime', FindTime);
      MaxRetry := LIni.ReadInteger('jevban', 'maxretry', MaxRetry);
      BanTime := LIni.ReadInt64('jevban', 'bantime', BanTime);
      BanIncrement := LIni.ReadBool('jevban', 'bantime.increment', BanIncrement);
      BanMax := LIni.ReadInt64('jevban', 'bantime.maxtime', BanMax);
      ContextLines := LIni.ReadInteger('jevban', 'context_lines', ContextLines);
      MaxClients := LIni.ReadInteger('jevban', 'max_clients', MaxClients);
      Flood4xx := LIni.ReadInteger('jevban', 'flood_4xx', Flood4xx);
      SignatureFile := LIni.ReadString('jevban', 'signatures', SignatureFile);
      BuiltinSignatures := LIni.ReadBool('jevban', 'builtin_signatures', BuiltinSignatures);
      SuspiciousScore := LIni.ReadInteger('jevban', 'suspicious_score', SuspiciousScore);
      Verbose := LIni.ReadBool('jevban', 'verbose', Verbose);
      Nice := LIni.ReadInteger('jevban', 'nice', Nice);

      Mode := LowerCase(LIni.ReadString('decider', 'mode', Mode));
      Provider := LowerCase(Trim(LIni.ReadString('decider', 'provider', '')));
      LUrlSet := Trim(LIni.ReadString('decider', 'url', '')) <> '';
      if LUrlSet then
        JevUrl := Trim(LIni.ReadString('decider', 'url', ''));
      LocalModel := LIni.ReadString('decider', 'local_model', LocalModel);
      if LIni.ReadString('decider', 'model_dir', '') <> '' then
        ModelDir := LIni.ReadString('decider', 'model_dir', '');
      if LIni.ReadString('decider', 'llama_lib_dir', '') <> '' then
        LlamaLibDir := LIni.ReadString('decider', 'llama_lib_dir', '');
      Threads := LIni.ReadInteger('decider', 'threads', Threads);
      GpuLayers := LIni.ReadInteger('decider', 'gpu_layers', GpuLayers);
      CtxTokens := LIni.ReadInteger('decider', 'ctx', CtxTokens);
      ReadoutT := F('readout_t', ReadoutT);
      NoulT := F('noul_t', NoulT);
      NoulBias := F('noul_bias', NoulBias);
      JevKey := LIni.ReadString('decider', 'api_key', JevKey);
      LModelSet := Trim(LIni.ReadString('decider', 'model', '')) <> '';
      if LModelSet then
        JevModel := Trim(LIni.ReadString('decider', 'model', ''));
      TimeoutMs := LIni.ReadInteger('decider', 'timeout_ms', TimeoutMs);
      Threshold := F('threshold', Threshold);
      InstantThreshold := F('instant_threshold', InstantThreshold);
      CacheSecs := LIni.ReadInteger('decider', 'cache_secs', CacheSecs);
      CachePassSecs := LIni.ReadInteger('decider', 'cache_pass_secs', CachePassSecs);
      BatchInterval := LIni.ReadInteger('decider', 'batch_interval', BatchInterval);
      BatchLines := LIni.ReadInteger('decider', 'batch_lines', BatchLines);
      BatchClients := LIni.ReadInteger('decider', 'batch_clients', BatchClients);
      AskIntent := LIni.ReadBool('decider', 'ask_intent', AskIntent);
      MaxPerMinute := LIni.ReadInteger('decider', 'max_per_minute', MaxPerMinute);
      OnError := LowerCase(LIni.ReadString('decider', 'on_error', OnError));
      RulesMinScore := LIni.ReadInteger('decider', 'rules_min_score', RulesMinScore);
      RulesInstantScore := LIni.ReadInteger('decider', 'rules_instant_score', RulesInstantScore);
      OverrideScore := LIni.ReadInteger('decider', 'override_score', OverrideScore);
      ReviewThreshold := F('review_threshold', ReviewThreshold);
      Shadow := LIni.ReadBool('decider', 'shadow', Shadow);
      if Trim(LIni.ReadString('jevban', 'badpaths', '')) <> '' then
        BadPathsFile := Trim(LIni.ReadString('jevban', 'badpaths', ''));
      Site := LIni.ReadString('decider', 'site', Site);
      Question := LIni.ReadString('decider', 'question', Question);

      ActionType := LowerCase(LIni.ReadString('action', 'type', ActionType));
      ActionName := LIni.ReadString('action', 'name', ActionName);
      Port := LIni.ReadString('action', 'port', Port);
      Jail := LIni.ReadString('action', 'jail', Jail);
      ActionStart := LIni.ReadString('action', 'actionstart', '');
      ActionStop := LIni.ReadString('action', 'actionstop', '');
      ActionBan := LIni.ReadString('action', 'actionban', '');
      ActionUnban := LIni.ReadString('action', 'actionunban', '');
      DryRun := LIni.ReadBool('action', 'dry_run', DryRun);
      CleanupOnExit := LIni.ReadBool('action', 'cleanup_on_exit', CleanupOnExit);
    finally
      LIni.Free;
    end;

    { the command line wins }
    if LCliLogs.Count > 0 then
      LogPaths.Assign(LCliLogs);
    LVal := LCli.Values['from_start'];
    if LVal <> '' then
      FromStart := True;
    if LCli.Values['shadow'] <> '' then
      Shadow := True;
    if LCli.Values['dry_run'] <> '' then
      DryRun := True;
    if LCli.Values['mode'] <> '' then
      Mode := LowerCase(LCli.Values['mode']);
    if LCli.Values['provider'] <> '' then
    begin
      Provider := LowerCase(LCli.Values['provider']);
      LUrlSet := False;
      LModelSet := False;
    end;
    if LCli.Values['url'] <> '' then
    begin
      LUrlSet := True;
      JevUrl := LCli.Values['url'];
      if LCli.Values['mode'] = '' then
        Mode := 'jev';   { --jev-url alone means: use that server }
    end;
    if LCli.Values['local_model'] <> '' then
      LocalModel := LCli.Values['local_model'];
    if LCli.Values['batch_interval'] <> '' then
      BatchInterval := StrToIntDef(LCli.Values['batch_interval'], BatchInterval);
    if LCli.Values['type'] <> '' then
      ActionType := LowerCase(LCli.Values['type']);
    if Provider <> '' then
    begin
      if LCli.Values['mode'] = '' then
        Mode := 'jev';
      ApplyProvider(LUrlSet, LModelSet);
    end;
    if JevKey = '' then
      JevKey := GetEnvironmentVariable('JEV_API_KEY');
    if TestMode then
    begin
      FromStart := True;
      DryRun := True;
    end;
  finally
    LCliLogs.Free;
    LCli.Free;
  end;
end;

procedure TBanConfig.ApplyProvider(AUrlSet, AModelSet: Boolean);
var
  I: Integer;
  P: TProviderInfo;
begin
  for I := 0 to High(CProviders) do
    if CProviders[I].Name = Provider then
    begin
      P := CProviders[I];
      if not AUrlSet then
        JevUrl := P.Url;
      if not AModelSet then
        JevModel := P.Model;
      if JevKey = '' then
        JevKey := GetEnvironmentVariable(P.KeyEnv);
      if P.MaxQuestions > 0 then
        BatchClients := Min(BatchClients, P.MaxQuestions);
      if P.MaxPerMinute > 0 then
        MaxPerMinute := Min(MaxPerMinute, P.MaxPerMinute);
      Exit;
    end;
  raise EArgumentException.CreateFmt('unknown provider "%s" (%s)', [Provider, ProviderNames]);
end;

procedure TBanConfig.Validate;
var
  I: Integer;

  function Safe(const S: string; const AExtra: TSysCharSet): Boolean;
  var
    C: Char;
  begin
    Result := S <> '';
    for C in S do
      if not (C in ['A'..'Z', 'a'..'z', '0'..'9', '_', '-'] + AExtra) then
        Exit(False);
  end;

begin
  IgnoreIp := ParseCidrList(IgnoreIpText);
  if (LogPaths.Count = 0) and not ListBans then
    raise EArgumentException.Create('no log to follow: set logpath in [jevban] or pass --log');
  if (Mode <> 'local') and (Mode <> 'jev') and (Mode <> 'rules') then
    raise EArgumentException.CreateFmt('mode must be local, jev or rules, not "%s"', [Mode]);
  { the hosted Jev API names its models jev-*; "openjev" is what the OpenJev helper ignores }
  if (Pos('api.typesafe.ai', LowerCase(JevUrl)) > 0) and (JevModel = 'openjev') then
    JevModel := 'jev-latest';
  { two questions per client with ask_intent: keep the batch under the provider's cap }
  if AskIntent and (Provider = 'abacus') then
    BatchClients := Min(BatchClients, 5);
  if (Mode = 'jev') and (Provider <> '') and (JevKey = '') then
    for I := 0 to High(CProviders) do
      if CProviders[I].Name = Provider then
        raise EArgumentException.CreateFmt('provider %s needs an API key: set api_key in [decider], or %s ' +
          'or JEV_API_KEY in the environment', [Provider, CProviders[I].KeyEnv]);
  if SameText(BadPathsFile, 'off') then
    BadPathsFile := ''
  else if (BadPathsFile <> '') and not FileExists(BadPathsFile) then
  begin
    { the default next to the binary is optional; a configured one is not }
    if BadPathsFile <> ExtractFilePath(ParamStr(0)) + 'badpaths.txt' then
      raise EArgumentException.CreateFmt('badpaths file %s not found', [BadPathsFile]);
    BadPathsFile := '';
  end;
  if CtxTokens < 1024 then
    CtxTokens := 1024;
  if (OnError <> 'rules') and (OnError <> 'skip') then
    raise EArgumentException.CreateFmt('on_error must be rules or skip, not "%s"', [OnError]);
  if (Threshold <= 0) or (Threshold > 1) or (InstantThreshold <= 0) or (InstantThreshold > 1) then
    raise EArgumentException.Create('threshold and instant_threshold are probabilities in (0, 1]');
  if (MaxRetry < 1) or (FindTime < 1) or (BanTime < 1) then
    raise EArgumentException.Create('maxretry, findtime and bantime must be positive');
  if (BatchInterval < 0) or (BatchLines < 1) or (BatchClients < 1) or (BatchClients > 50) then
    raise EArgumentException.Create('batch_interval >= 0, batch_lines >= 1, batch_clients 1..50 ' +
      '(the decider reads at most 52 options per question, and 16k tokens per request)');
  if ContextLines < 1 then
    ContextLines := 1;
  if PollMs < 20 then
    PollMs := 20;
  { these go into shell commands; they come from root's config, but a typo
    should fail here, not as a half-applied firewall rule }
  if not Safe(ActionName, []) then
    raise EArgumentException.Create('action name: letters, digits, _ and - only');
  if not Safe(Jail, []) then
    raise EArgumentException.Create('action jail: letters, digits, _ and - only');
  if not Safe(Port, [',', ':', ' ']) then
    raise EArgumentException.Create('action port: e.g. 80,443');
end;

end.
