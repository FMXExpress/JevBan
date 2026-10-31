unit Ban.Firewall;

(* Firewall actions in the fail2ban mould: actionstart once at startup,
   actionban / actionunban per address, actionstop at shutdown. Each is a
   shell command line (/bin/sh -c, cmd.exe /c on Windows) with tags:
     <ip>        the address, canonical (only ever a parsed address)
     <v>         4 or 6;  <family> inet or inet6;  <fwfamily> ipv4 or ipv6
     <iptables>  iptables or ip6tables; a start/stop command using it runs
                 once per family
     <name> <port> <jail> <bantime>
   Presets: iptables (default), nftables, ufw, firewalld, fail2ban (hands the
   address to a fail2ban jail), netsh (Windows), none (log only). Any of the
   four commands set in the config replaces the preset's. *)

{$mode objfpc}{$H+}

interface

uses
  SysUtils, Classes, Process, SyncObjs, Ban.Net;

type
  TLogProc = procedure(const AMsg: string) of object;

  TBanAction = class
  private
    FLog: TLogProc;
    function Expand(const ACmd: string; const AIp: TIpAddr; AHasIp: Boolean;
      const AIptables: string; ABanSecs: Int64): string;
    { AQuiet: a failure is not logged (a batch whose retries report it) }
    function Run(const ACmd: string; AQuiet: Boolean = False): Boolean;
    procedure RunLifecycle(const ACmd, AWhat: string);
    procedure Say(const AMsg: string);
  public
    Kind: string;
    Name: string;
    Port: string;
    Jail: string;
    StartCmd, StopCmd, BanCmd, UnbanCmd: string;
    DryRun: Boolean;
    (* the preset's own ban and unban commands are in use (not the config's):
       ipset, nftables and iptables then take a whole batch in one process *)
    BatchKind: string;
    constructor Create(ALog: TLogProc);
    { fills the four commands from Kind; raises on an unknown preset }
    procedure ApplyPreset;
    procedure Start;
    procedure Stop;
    function Ban(const AIp: TIpAddr; ABanSecs: Int64): Boolean;
    function Unban(const AIp: TIpAddr): Boolean;
    (* many at once: one ipset restore, nft -f or iptables-restore per batch
       where the preset allows, else one command each. A batch that fails (an
       unban of an address the firewall no longer has aborts nft -f and
       iptables-restore) is retried one by one, so each failure is reported *)
    procedure BanMany(const AIps: array of TIpAddr; const ASecs: array of Int64);
    procedure UnbanMany(const AIps: array of TIpAddr);
  end;

  TActionJob = record
    Ban: Boolean;
    Ip: TIpAddr;
    Secs: Int64;
  end;

  (* runs the firewall commands off the thread that reads the log: starting a
     shell and a firewall tool takes 30-40 ms (ufw and firewalld far more),
     which in a ban storm of thousands of addresses stalled reading for
     minutes. Jobs queued meanwhile go to the firewall in one batch *)
  TActionWorker = class(TThread)
  private
    FAction: TBanAction;
    FLock: TCriticalSection;
    FWake: TEvent;
    FJobs: array of TActionJob;
    FCount: Integer;
    FBusy: Boolean;
    procedure RunJobs(const AJobs: array of TActionJob; ACount: Integer);
  protected
    procedure Execute; override;
  public
    constructor Create(AAction: TBanAction);
    destructor Destroy; override;
    procedure Ban(const AIp: TIpAddr; ASecs: Int64);
    procedure Unban(const AIp: TIpAddr);
    { waits until everything queued so far has run }
    procedure Drain;
  end;

implementation

constructor TBanAction.Create(ALog: TLogProc);
begin
  inherited Create;
  FLog := ALog;
  Kind := 'iptables';
  Name := 'jevban';
  Port := '80,443';
  Jail := 'jevban';
end;

procedure TBanAction.Say(const AMsg: string);
begin
  if Assigned(FLog) then
    FLog(AMsg);
end;

procedure TBanAction.ApplyPreset;
var
  LStart, LStop, LBan, LUnban: string;
begin
  LStart := '';
  LStop := '';
  LBan := '';
  LUnban := '';
  if Kind = 'iptables' then
  begin
    { a chain of our own, hooked into INPUT for the web ports; flushed at
      start so restored bans are not duplicated }
    LStart := '<iptables> -N <name> 2>/dev/null; <iptables> -F <name> && ' +
      '{ <iptables> -C INPUT -p tcp -m multiport --dports <port> -j <name> 2>/dev/null || ' +
      '<iptables> -I INPUT -p tcp -m multiport --dports <port> -j <name>; }';
    LStop := '<iptables> -D INPUT -p tcp -m multiport --dports <port> -j <name>; ' +
      '<iptables> -F <name>; <iptables> -X <name>';
    LBan := '<iptables> -I <name> 1 -s <ip> -j DROP';
    LUnban := '<iptables> -D <name> -s <ip> -j DROP';
  end
  else if Kind = 'ipset' then
  begin
    { iptables with the bans in a hash set: one rule however many addresses, where
      the iptables preset adds a rule per address (checked one by one per packet) }
    LStart := 'ipset create <name><v6suffix> hash:ip <ipsetfamily> -exist && ipset flush <name><v6suffix> && ' +
      '{ <iptables> -C INPUT -p tcp -m multiport --dports <port> -m set --match-set <name><v6suffix> src -j DROP ' +
      '2>/dev/null || <iptables> -I INPUT -p tcp -m multiport --dports <port> -m set --match-set <name><v6suffix> ' +
      'src -j DROP; }';
    LStop := '<iptables> -D INPUT -p tcp -m multiport --dports <port> -m set --match-set <name><v6suffix> src ' +
      '-j DROP; ipset destroy <name><v6suffix>';
    LBan := 'ipset add <name><v6suffix> <ip> -exist';
    LUnban := 'ipset del <name><v6suffix> <ip> -exist';
  end
  else if Kind = 'nftables' then
  begin
    LStart := 'nft add table inet <name> && ' +
      'nft ''add set inet <name> v4 { type ipv4_addr; }'' && ' +
      'nft ''add set inet <name> v6 { type ipv6_addr; }'' && ' +
      'nft ''add chain inet <name> input { type filter hook input priority -1; }'' && ' +
      'nft flush chain inet <name> input && nft flush set inet <name> v4 && nft flush set inet <name> v6 && ' +
      'nft ''add rule inet <name> input ip saddr @v4 tcp dport { <port> } drop'' && ' +
      'nft ''add rule inet <name> input ip6 saddr @v6 tcp dport { <port> } drop''';
    LStop := 'nft delete table inet <name>';
    LBan := 'nft add element inet <name> v<v> { <ip> }';
    LUnban := 'nft delete element inet <name> v<v> { <ip> }';
  end
  else if Kind = 'ufw' then
  begin
    LBan := 'ufw prepend deny from <ip> to any port <port> proto tcp';
    LUnban := 'ufw delete deny from <ip> to any port <port> proto tcp';
  end
  else if Kind = 'firewalld' then
  begin
    { runtime rules only: jevban restores its bans itself after a restart }
    LBan := 'firewall-cmd --add-rich-rule="rule family=<fwfamily> source address=<ip> drop"';
    LUnban := 'firewall-cmd --remove-rich-rule="rule family=<fwfamily> source address=<ip> drop"';
  end
  else if Kind = 'fail2ban' then
  begin
    LBan := 'fail2ban-client set <jail> banip <ip>';
    LUnban := 'fail2ban-client set <jail> unbanip <ip>';
  end
  else if Kind = 'netsh' then
  begin
    LBan := 'netsh advfirewall firewall add rule name="<name> <ip>" dir=in action=block remoteip=<ip>';
    LUnban := 'netsh advfirewall firewall delete rule name="<name> <ip>"';
  end
  else if (Kind <> 'none') and (Kind <> 'command') then
    raise Exception.CreateFmt('unknown action type "%s" (iptables, ipset, nftables, ufw, firewalld, ' +
      'fail2ban, netsh, command, none)', [Kind]);
  { the config's own commands win over the preset }
  if (BanCmd = '') and (UnbanCmd = '') and ((Kind = 'ipset') or (Kind = 'nftables') or (Kind = 'iptables')) then
    BatchKind := Kind
  else
    BatchKind := '';
  if StartCmd = '' then
    StartCmd := LStart;
  if StopCmd = '' then
    StopCmd := LStop;
  if BanCmd = '' then
    BanCmd := LBan;
  if UnbanCmd = '' then
    UnbanCmd := LUnban;
  if (Kind = 'command') and (BanCmd = '') then
    raise Exception.Create('action type "command" needs actionban');
end;

function TBanAction.Expand(const ACmd: string; const AIp: TIpAddr; AHasIp: Boolean;
  const AIptables: string; ABanSecs: Int64): string;
begin
  Result := ACmd;
  if AHasIp then
  begin
    Result := StringReplace(Result, '<ip>', IpToStr(AIp), [rfReplaceAll]);
    if AIp.IsV4 then
    begin
      Result := StringReplace(Result, '<v>', '4', [rfReplaceAll]);
      Result := StringReplace(Result, '<family>', 'inet', [rfReplaceAll]);
      Result := StringReplace(Result, '<fwfamily>', 'ipv4', [rfReplaceAll]);
      Result := StringReplace(Result, '<iptables>', 'iptables', [rfReplaceAll]);
      Result := StringReplace(Result, '<v6suffix>', '', [rfReplaceAll]);
    end
    else
    begin
      Result := StringReplace(Result, '<v6suffix>', '6', [rfReplaceAll]);
      Result := StringReplace(Result, '<v>', '6', [rfReplaceAll]);
      Result := StringReplace(Result, '<family>', 'inet6', [rfReplaceAll]);
      Result := StringReplace(Result, '<fwfamily>', 'ipv6', [rfReplaceAll]);
      Result := StringReplace(Result, '<iptables>', 'ip6tables', [rfReplaceAll]);
    end;
  end
  else
  begin
    Result := StringReplace(Result, '<iptables>', AIptables, [rfReplaceAll]);
    { start/stop run once per family: the IPv6 set is <name>6 }
    if AIptables = 'ip6tables' then
    begin
      Result := StringReplace(Result, '<v6suffix>', '6', [rfReplaceAll]);
      Result := StringReplace(Result, '<ipsetfamily>', 'family inet6', [rfReplaceAll]);
    end
    else
    begin
      Result := StringReplace(Result, '<v6suffix>', '', [rfReplaceAll]);
      Result := StringReplace(Result, '<ipsetfamily>', 'family inet', [rfReplaceAll]);
    end;
  end;
  Result := StringReplace(Result, '<name>', Name, [rfReplaceAll]);
  Result := StringReplace(Result, '<port>', Port, [rfReplaceAll]);
  Result := StringReplace(Result, '<jail>', Jail, [rfReplaceAll]);
  Result := StringReplace(Result, '<bantime>', IntToStr(ABanSecs), [rfReplaceAll]);
end;

function TBanAction.Run(const ACmd: string; AQuiet: Boolean): Boolean;
var
  LProc: TProcess;
  LOut: TStringList;
begin
  if ACmd = '' then
    Exit(True);
  if DryRun then
  begin
    Say('[dry-run] ' + ACmd);
    Exit(True);
  end;
  LProc := TProcess.Create(nil);
  LOut := TStringList.Create;
  try
    {$IFDEF WINDOWS}
    LProc.Executable := GetEnvironmentVariable('COMSPEC');
    if LProc.Executable = '' then
      LProc.Executable := 'cmd.exe';
    LProc.Parameters.Add('/c');
    {$ELSE}
    LProc.Executable := '/bin/sh';
    LProc.Parameters.Add('-c');
    {$ENDIF}
    LProc.Parameters.Add(ACmd);
    LProc.Options := [poWaitOnExit, poUsePipes, poStderrToOutPut];
    LProc.ShowWindow := swoHide;
    try
      LProc.Execute;
    except
      on E: Exception do
      begin
        Say(Format('action failed to start: %s (%s)', [ACmd, E.Message]));
        Exit(False);
      end;
    end;
    LOut.LoadFromStream(LProc.Output);
    Result := LProc.ExitStatus = 0;
    if not Result and not AQuiet then
      Say(Format('action exit %d: %s%s', [LProc.ExitStatus, ACmd,
        StringReplace(' | ' + Trim(LOut.Text), LineEnding, ' | ', [rfReplaceAll])]));
  finally
    LOut.Free;
    LProc.Free;
  end;
end;

procedure TBanAction.RunLifecycle(const ACmd, AWhat: string);
var
  LNone: TIpAddr;
begin
  if ACmd = '' then
    Exit;
  LNone := Default(TIpAddr);
  if Pos('<iptables>', ACmd) > 0 then
  begin
    if not Run(Expand(ACmd, LNone, False, 'iptables', 0)) then
      Say(AWhat + ' failed for IPv4');
    { many hosts have no ip6tables; not fatal }
    if not Run(Expand(ACmd, LNone, False, 'ip6tables', 0)) then
      Say(AWhat + ' failed for IPv6 (IPv6 bans will not work)');
  end
  else if not Run(Expand(ACmd, LNone, False, '', 0)) then
    Say(AWhat + ' failed');
end;

procedure TBanAction.Start;
begin
  RunLifecycle(StartCmd, 'actionstart');
end;

procedure TBanAction.Stop;
begin
  RunLifecycle(StopCmd, 'actionstop');
end;

function TBanAction.Ban(const AIp: TIpAddr; ABanSecs: Int64): Boolean;
begin
  Result := Run(Expand(BanCmd, AIp, True, '', ABanSecs));
end;

function TBanAction.Unban(const AIp: TIpAddr): Boolean;
begin
  Result := Run(Expand(UnbanCmd, AIp, True, '', 0));
end;

function BatchScript(const AKind: string; ABan: Boolean; const ALinesV4, ALinesV6: string): string;
const
  CEnd = 'JEVBAN_EOF';
begin
  Result := '';
  if AKind = 'ipset' then
    Result := 'ipset -exist restore <<''' + CEnd + '''' + LineEnding + ALinesV4 + ALinesV6 + CEnd + LineEnding
  else if AKind = 'nftables' then
    Result := 'nft -f - <<''' + CEnd + '''' + LineEnding + ALinesV4 + ALinesV6 + CEnd + LineEnding
  else if AKind = 'iptables' then
  begin
    if ALinesV4 <> '' then
      Result := 'iptables-restore --noflush <<''' + CEnd + '''' + LineEnding + '*filter' + LineEnding + ALinesV4 +
        'COMMIT' + LineEnding + CEnd + LineEnding;
    if ALinesV6 <> '' then
    begin
      if Result <> '' then
        Result := Result + '[ $? -eq 0 ] || exit 1' + LineEnding;
      Result := Result + 'ip6tables-restore --noflush <<''' + CEnd + '''' + LineEnding + '*filter' + LineEnding +
        ALinesV6 + 'COMMIT' + LineEnding + CEnd + LineEnding;
    end;
  end;
end;

function BatchLine(const AKind: string; ABan: Boolean): string;
begin
  if AKind = 'ipset' then
  begin
    if ABan then Result := 'add <name><v6suffix> <ip>' else Result := 'del <name><v6suffix> <ip>';
  end
  else if AKind = 'nftables' then
  begin
    if ABan then Result := 'add element inet <name> v<v> { <ip> }' else Result := 'delete element inet <name> v<v> { <ip> }';
  end
  else if ABan then
    Result := '-I <name> 1 -s <ip> -j DROP'
  else
    Result := '-D <name> -s <ip> -j DROP';
end;

procedure TBanAction.BanMany(const AIps: array of TIpAddr; const ASecs: array of Int64);
var
  I: Integer;
  L4, L6, LLine: string;
begin
  if Length(AIps) = 0 then
    Exit;
  if (BatchKind <> '') and not DryRun and (Length(AIps) > 1) then
  begin
    L4 := '';
    L6 := '';
    for I := 0 to High(AIps) do
    begin
      LLine := Expand(BatchLine(BatchKind, True), AIps[I], True, '', ASecs[I]) + LineEnding;
      if AIps[I].IsV4 then L4 := L4 + LLine else L6 := L6 + LLine;
    end;
    if Run(BatchScript(BatchKind, True, L4, L6), True) then
      Exit;
    Say(Format('batch of %d bans failed; one by one', [Length(AIps)]));
  end;
  for I := 0 to High(AIps) do
    Ban(AIps[I], ASecs[I]);
end;

procedure TBanAction.UnbanMany(const AIps: array of TIpAddr);
var
  I: Integer;
  L4, L6, LLine: string;
begin
  if Length(AIps) = 0 then
    Exit;
  if (BatchKind <> '') and not DryRun and (Length(AIps) > 1) then
  begin
    L4 := '';
    L6 := '';
    for I := 0 to High(AIps) do
    begin
      LLine := Expand(BatchLine(BatchKind, False), AIps[I], True, '', 0) + LineEnding;
      if AIps[I].IsV4 then L4 := L4 + LLine else L6 := L6 + LLine;
    end;
    if Run(BatchScript(BatchKind, False, L4, L6), True) then
      Exit;
    { quietly: an unban of something already gone is the usual cause }
  end;
  for I := 0 to High(AIps) do
    Unban(AIps[I]);
end;

{ TActionWorker }

constructor TActionWorker.Create(AAction: TBanAction);
begin
  FAction := AAction;
  FLock := TCriticalSection.Create;
  FWake := TEvent.Create(nil, False, False, '');
  inherited Create(False);
end;

destructor TActionWorker.Destroy;
begin
  { what is queued still runs: Execute drains before it returns }
  Terminate;
  FWake.SetEvent;
  inherited Destroy;
  FWake.Free;
  FLock.Free;
end;

procedure TActionWorker.Ban(const AIp: TIpAddr; ASecs: Int64);
begin
  FLock.Enter;
  try
    if FCount = Length(FJobs) then
      SetLength(FJobs, Length(FJobs) * 2 + 64);
    FJobs[FCount].Ban := True;
    FJobs[FCount].Ip := AIp;
    FJobs[FCount].Secs := ASecs;
    Inc(FCount);
  finally
    FLock.Leave;
  end;
  FWake.SetEvent;
end;

procedure TActionWorker.Unban(const AIp: TIpAddr);
begin
  FLock.Enter;
  try
    if FCount = Length(FJobs) then
      SetLength(FJobs, Length(FJobs) * 2 + 64);
    FJobs[FCount].Ban := False;
    FJobs[FCount].Ip := AIp;
    FJobs[FCount].Secs := 0;
    Inc(FCount);
  finally
    FLock.Leave;
  end;
  FWake.SetEvent;
end;

procedure TActionWorker.Drain;
var
  LDone: Boolean;
begin
  repeat
    FLock.Enter;
    try
      LDone := (FCount = 0) and not FBusy;
    finally
      FLock.Leave;
    end;
    if not LDone then
      Sleep(10);
  until LDone;
end;

{ in order, a run of bans or of unbans at a time: an unban queued after a ban of
  the same address must come after it }
procedure TActionWorker.RunJobs(const AJobs: array of TActionJob; ACount: Integer);
var
  I, J, K: Integer;
  LIps: array of TIpAddr;
  LSecs: array of Int64;
begin
  I := 0;
  while I < ACount do
  begin
    J := I;
    while (J < ACount) and (AJobs[J].Ban = AJobs[I].Ban) do
      Inc(J);
    SetLength(LIps, J - I);
    SetLength(LSecs, J - I);
    for K := I to J - 1 do
    begin
      LIps[K - I] := AJobs[K].Ip;
      LSecs[K - I] := AJobs[K].Secs;
    end;
    if AJobs[I].Ban then
      FAction.BanMany(LIps, LSecs)
    else
      FAction.UnbanMany(LIps);
    I := J;
  end;
end;

procedure TActionWorker.Execute;
var
  LJobs: array of TActionJob;
  N: Integer;
begin
  repeat
    FWake.WaitFor(500);
    FLock.Enter;
    try
      LJobs := Copy(FJobs, 0, FCount);
      N := FCount;
      FCount := 0;
      FBusy := N > 0;
    finally
      FLock.Leave;
    end;
    if N > 0 then
    try
      RunJobs(LJobs, N);
    except
      on E: Exception do
        FAction.Say('action worker: ' + E.Message);
    end;
    FLock.Enter;
    try
      FBusy := False;
    finally
      FLock.Leave;
    end;
  until Terminated and (FCount = 0);
end;

end.
