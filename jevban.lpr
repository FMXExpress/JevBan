program jevban;

(* jevban: fail2ban for web attackers, with a Jev-style decision model as
   the judge. It follows Apache access logs, flags requests that look like
   security probes (/.env, /wp-login.php, ../, ${jndi:, sqlmap, ...), asks
   the decision API (OpenJev or the hosted Jev API, POST /v1/systemone)
   whether that client is attacking, and hands the ones that are to the
   firewall (iptables, nftables, ufw, firewalld, a fail2ban jail, netsh). *)

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}cthreads, BaseUnix,{$ENDIF}
  {$IFDEF WINDOWS}Windows,{$ENDIF}
  SysUtils, Classes,
  Ban.Config, Ban.Tail, Ban.Engine, Ban.Jev;

var
  Cfg: TBanConfig;
  Engine: TBanEngine;
  Tailer: TLogTailer;
  Lines: TStringList;
  Line: string;
  Stopping: Boolean = False;

{$IFDEF UNIX}
procedure OnSignal(ASig: cint); cdecl;
begin
  { the first signal stops cleanly (bans saved, actionstop); a second one
    does not wait for a model decision in progress }
  if Stopping then
    FpExit(128 + ASig);
  Stopping := True;
  DeciderAbort := True;
end;

procedure InstallSignals;
begin
  FpSignal(SIGTERM, @OnSignal);
  FpSignal(SIGINT, @OnSignal);
  FpSignal(SIGPIPE, signalhandler(SIG_IGN));
  FpSignal(SIGHUP, signalhandler(SIG_IGN));
end;
{$ELSE}
procedure InstallSignals;
begin
end;
{$ENDIF}

{ --eval lines: "attack[:category]<TAB>log line" or "benign[:category]<TAB>log line" }
function SplitLabel(const ALine: string; out ATruth: Integer; out ACategory: string): string;
var
  LTab, LColon: Integer;
  LLabel: string;
begin
  ATruth := CTruthUnknown;
  ACategory := '';
  Result := ALine;
  LTab := Pos(#9, ALine);
  if LTab = 0 then
    Exit;
  LLabel := LowerCase(Trim(Copy(ALine, 1, LTab - 1)));
  LColon := Pos(':', LLabel);
  if LColon > 0 then
  begin
    ACategory := Copy(LLabel, 1, LColon - 1) + ':' + Copy(LLabel, LColon + 1, MaxInt);
    LLabel := Copy(LLabel, 1, LColon - 1);
  end;
  if LLabel = 'attack' then
    ATruth := CTruthAttack
  else if LLabel = 'benign' then
    ATruth := CTruthBenign
  else
    Exit;
  Result := Copy(ALine, LTab + 1, MaxInt);
end;

procedure RunTest;
var
  I, LTruth: Integer;
  LText, LCategory: string;
begin
  for I := 0 to Cfg.LogPaths.Count - 1 do
    if not FileExists(Cfg.LogPaths[I]) then
      raise EArgumentException.CreateFmt('%s not found', [Cfg.LogPaths[I]]);
  Engine.InitDecider;
  Engine.Log(Format('test run over %s, decider %s', [Tailer.FileNames, Engine.Describe]));
  while not Stopping and Tailer.Poll(Lines) do
  begin
    for I := 0 to Lines.Count - 1 do
    begin
      if Stopping then
        Break;
      Line := Lines[I];
      if Cfg.EvalMode then
      begin
        if (Line = '') or (Line[1] = '#') then
          Continue;
        LText := SplitLabel(Line, LTruth, LCategory);
        Engine.Feed(LText, LTruth, LCategory, Lines.Objects[I]);
      end
      else
        Engine.Feed(Line, CTruthUnknown, '', Lines.Objects[I]);
    end;
    Lines.Clear;
  end;
  Engine.FlushAll;
  Engine.Log(Engine.Summary);
  if Cfg.EvalMode then
    Engine.EvalReport(Cfg.EvalJson);
end;

{ the model may use every core; the web server should still come first }
procedure LowerPriority;
begin
  if Cfg.Nice <= 0 then
    Exit;
  {$IFDEF UNIX}
  { setpriority, not FpNice: x86-64 Linux has no nice syscall, and FPC 3.2.2's
    FpNice fails there with EINVAL. Threads started later (the decider worker,
    llama.cpp's pool) inherit it }
  if FpSetPriority(0, 0, Cfg.Nice) <> 0 then
    WriteLn(StdErr, 'jevban: could not lower the priority (errno ', FpGetErrno, ')');
  {$ENDIF}
  {$IFDEF WINDOWS}
  SetPriorityClass(GetCurrentProcess, BELOW_NORMAL_PRIORITY_CLASS);
  {$ENDIF}
end;

procedure RunDaemon;
var
  I: Integer;
begin
  LowerPriority;
  Engine.Start;
  Engine.InitDecider;
  Engine.Log(Format('following %s; decider %s; action %s%s', [Tailer.FileNames, Engine.Describe, Cfg.ActionType,
    BoolToStr(Cfg.DryRun, ' (dry run)', '')]));
  while not Stopping do
  begin
    Lines.Clear;
    if Tailer.Poll(Lines) then
      for I := 0 to Lines.Count - 1 do
      begin
        Engine.Feed(Lines[I], CTruthUnknown, '', Lines.Objects[I]);
        if Stopping then
          Break;
      end;
    Engine.Tick;
    if Lines.Count = 0 then
      Sleep(Cfg.PollMs);
  end;
  Engine.Log('stopping: ' + Engine.Summary);
  Engine.Stop;
end;

begin
  Cfg := TBanConfig.Create;
  Engine := nil;
  Tailer := nil;
  Lines := TStringList.Create;
  try
    try
      if not Cfg.Load then
        Exit;
      Cfg.Validate;
      Engine := TBanEngine.Create(Cfg);
      if Cfg.ListBans then
      begin
        Engine.PrintBans;
        Exit;
      end;
      InstallSignals;
      Tailer := TLogTailer.Create(Cfg.LogPaths, Cfg.FromStart);
      if Cfg.TestMode then
        RunTest
      else
        RunDaemon;
    except
      on E: EArgumentException do
      begin
        WriteLn(StdErr, 'jevban: ', E.Message);
        ExitCode := 2;
      end;
      on E: Exception do
      begin
        WriteLn(StdErr, 'jevban: ', E.ClassName, ': ', E.Message);
        ExitCode := 1;
      end;
    end;
  finally
    Tailer.Free;
    Engine.Free;
    Lines.Free;
    Cfg.Free;
  end;
end.
