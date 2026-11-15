unit Ban.Cloudflare;

(* Bans at Cloudflare's edge, for sites behind it: a firewall on the origin
   never sees the visitor's address there, only Cloudflare's.

   One account-level IP list (Lists API, kind "ip", default name jevban)
   holds every active ban, and one custom rule per zone blocks it:
     ip.src in $jevban
   so a client caught on one site is blocked on every site of the account,
   and a new zone gets its rule the next time jevban starts.

   The list is replaced whole after each batch of bans and unbans (PUT
   .../items, asynchronous; polled until it completes), from the set of
   active bans kept here: a failed update is put right by the next one, and
   entries left over from before a restart are removed by the first. The
   account allows one pending bulk operation at a time, which the action
   worker's single thread guarantees.

   Cloudflare being unreachable never stops jevban: the error is logged and
   the next batch tries again. *)

{$mode objfpc}{$H+}

interface

uses
  SysUtils, Classes, Math, DateUtils, fpjson, jsonparser, Ban.Net;

type
  TCfLogProc = procedure(const AMsg: string) of object;

  TCloudflare = class
  private
    FLog: TCfLogProc;
    FListId: string;
    FReady: Boolean;
    FActive: TStringList;   { the banned addresses, oldest first }
    FDirty: Boolean;        { FActive differs from what Cloudflare has }
    procedure Say(const AMsg: string);
    { calls the API; the "result" (owned by the caller) or nil with AError }
    function Call(const AMethod, APath, ABody: string; out AError: string; out AStatus: Integer): TJSONData;
    function FindOrCreateList(out AError: string): Boolean;
    function EnsureRules(out AError: string): Boolean;
    function EnsureZoneRule(const AZoneId, AZoneName: string; out AError: string): Boolean;
    function WaitForOperation(const AOpId: string; out AError: string): Boolean;
  public
    ApiBase: string;        { https://api.cloudflare.com/client/v4 }
    Token: string;
    AccountId: string;
    ListName: string;
    Zones: string;          { 'all', or comma-separated zone names }
    MakeRules: Boolean;     { add the blocking rule to each zone }
    MaxItems: Integer;      { the list's cap: the free plan allows 10,000 items in all }
    TimeoutMs: Integer;
    DryRun: Boolean;
    constructor Create(ALog: TCfLogProc);
    destructor Destroy; override;
    { finds or creates the list and the zones' rules; False (logged) if Cloudflare cannot be reached }
    function Setup: Boolean;
    procedure Ban(const AIps: array of TIpAddr);
    procedure Unban(const AIps: array of TIpAddr);
    { the whole list as the active bans; logged on failure, retried by the next call }
    function Sync: Boolean;
    { empties the list (on stop, with cleanup_on_exit) }
    procedure Clear;
    function ActiveCount: Integer;
    function RuleExpression: string;
  end;

implementation

uses
  Ban.Https;

constructor TCloudflare.Create(ALog: TCfLogProc);
begin
  inherited Create;
  FLog := ALog;
  FActive := TStringList.Create;
  ApiBase := 'https://api.cloudflare.com/client/v4';
  ListName := 'jevban';
  Zones := 'all';
  MakeRules := True;
  MaxItems := 10000;
  TimeoutMs := 15000;
end;

destructor TCloudflare.Destroy;
begin
  FActive.Free;
  inherited Destroy;
end;

procedure TCloudflare.Say(const AMsg: string);
begin
  if Assigned(FLog) then
    FLog('cloudflare: ' + AMsg);
end;

function TCloudflare.RuleExpression: string;
begin
  Result := 'ip.src in $' + ListName;
end;

function TCloudflare.ActiveCount: Integer;
begin
  Result := FActive.Count;
end;

function TCloudflare.Call(const AMethod, APath, ABody: string; out AError: string; out AStatus: Integer): TJSONData;
var
  LResp: string;
  LData, LErrs: TJSONData;
begin
  Result := nil;
  AError := '';
  AStatus := 0;
  try
    LResp := HttpJson(AMethod, ApiBase + APath, ABody, ['Authorization', 'Bearer ' + Token,
      'User-Agent', 'jevban'], TimeoutMs, AStatus);
  except
    on E: Exception do
    begin
      AError := Format('%s %s: %s', [AMethod, APath, E.Message]);
      Exit;
    end;
  end;
  try
    LData := GetJSON(LResp);
  except
    AError := Format('%s %s: HTTP %d, not JSON: %s', [AMethod, APath, AStatus, Copy(LResp, 1, 160)]);
    Exit;
  end;
  try
    (* the envelope: {"success": .., "errors": [{"code": .., "message": ..}], "result": ..} *)
    if (LData.JSONType = jtObject) and TJSONObject(LData).Get('success', False) then
    begin
      Result := TJSONObject(LData).Extract('result');
      if Result = nil then
        Result := TJSONNull.Create;
      Exit;
    end;
    AError := Format('%s %s: HTTP %d', [AMethod, APath, AStatus]);
    if LData.JSONType = jtObject then
    begin
      LErrs := TJSONObject(LData).Find('errors');
      if (LErrs <> nil) and (LErrs.JSONType = jtArray) and (TJSONArray(LErrs).Count > 0) and
         (TJSONArray(LErrs).Items[0].JSONType = jtObject) then
        AError := AError + Format(', %d %s', [TJSONObject(TJSONArray(LErrs).Items[0]).Get('code', 0),
          TJSONObject(TJSONArray(LErrs).Items[0]).Get('message', '')]);
    end;
  finally
    LData.Free;
  end;
end;

function TCloudflare.FindOrCreateList(out AError: string): Boolean;
var
  R: TJSONData;
  LStatus, I: Integer;
  O: TJSONObject;
begin
  Result := False;
  R := Call('GET', '/accounts/' + AccountId + '/rules/lists', '', AError, LStatus);
  if R = nil then
    Exit;
  try
    if R.JSONType = jtArray then
      for I := 0 to TJSONArray(R).Count - 1 do
        if TJSONArray(R).Items[I].JSONType = jtObject then
        begin
          O := TJSONObject(TJSONArray(R).Items[I]);
          if O.Get('name', '') = ListName then
          begin
            if O.Get('kind', '') <> 'ip' then
            begin
              AError := Format('list %s exists but holds %s, not IP addresses', [ListName, O.Get('kind', '')]);
              Exit;
            end;
            FListId := O.Get('id', '');
            Exit(FListId <> '');
          end;
        end;
  finally
    R.Free;
  end;
  { not there: create it }
  O := TJSONObject.Create(['kind', 'ip', 'name', ListName,
    'description', 'Addresses banned by jevban (managed by jevban: edits are overwritten)']);
  try
    R := Call('POST', '/accounts/' + AccountId + '/rules/lists', O.AsJSON, AError, LStatus);
  finally
    O.Free;
  end;
  if R = nil then
  begin
    { the free plan allows one custom list }
    AError := AError + Format(' (creating list %s; the free plan allows one custom list: set list = to an ' +
      'existing IP list to use that)', [ListName]);
    Exit;
  end;
  try
    if R.JSONType = jtObject then
      FListId := TJSONObject(R).Get('id', '');
    Result := FListId <> '';
    if Result then
      Say(Format('created IP list %s', [ListName]));
  finally
    R.Free;
  end;
end;

function TCloudflare.EnsureZoneRule(const AZoneId, AZoneName: string; out AError: string): Boolean;
var
  R, LRules: TJSONData;
  LStatus, I: Integer;
  LRule, LBody: TJSONObject;
  LRulesetId, LExpr: string;
begin
  Result := False;
  LExpr := RuleExpression;
  R := Call('GET', '/zones/' + AZoneId + '/rulesets/phases/http_request_firewall_custom/entrypoint', '', AError,
    LStatus);
  if (R = nil) and (LStatus <> 404) then
    Exit;
  LRule := TJSONObject.Create(['action', 'block', 'expression', LExpr,
    'description', 'jevban: addresses it banned (list ' + ListName + ')', 'enabled', True]);
  try
    if R = nil then
    begin
      { no custom rules in this zone yet: create its entry point ruleset with ours }
      LBody := TJSONObject.Create(['name', 'default', 'kind', 'zone', 'phase', 'http_request_firewall_custom',
        'rules', TJSONArray.Create([LRule.Clone])]);
      try
        R := Call('POST', '/zones/' + AZoneId + '/rulesets', LBody.AsJSON, AError, LStatus);
      finally
        LBody.Free;
      end;
      if R = nil then
        Exit;
      R.Free;
      Say(Format('%s: created its custom rules with "%s"', [AZoneName, LExpr]));
      Exit(True);
    end;
    try
      LRulesetId := '';
      if R.JSONType = jtObject then
      begin
        LRulesetId := TJSONObject(R).Get('id', '');
        LRules := TJSONObject(R).Find('rules');
        if (LRules <> nil) and (LRules.JSONType = jtArray) then
          for I := 0 to TJSONArray(LRules).Count - 1 do
            if (TJSONArray(LRules).Items[I].JSONType = jtObject) and
               (Pos('$' + ListName, TJSONObject(TJSONArray(LRules).Items[I]).Get('expression', '')) > 0) then
              Exit(True);   { a rule using the list is there (ours, or the owner's) }
      end;
    finally
      R.Free;
    end;
    if LRulesetId = '' then
    begin
      AError := AZoneName + ': its custom rules ruleset has no id';
      Exit;
    end;
    R := Call('POST', '/zones/' + AZoneId + '/rulesets/' + LRulesetId + '/rules', LRule.AsJSON, AError, LStatus);
    if R = nil then
    begin
      AError := AError + ' (the free plan allows five custom rules per zone)';
      Exit;
    end;
    R.Free;
    Say(Format('%s: added the rule "%s"', [AZoneName, LExpr]));
    Result := True;
  finally
    LRule.Free;
  end;
end;

function TCloudflare.EnsureRules(out AError: string): Boolean;
var
  R: TJSONData;
  LStatus, I, LPage, LDone, LFailed: Integer;
  O: TJSONObject;
  LWant: TStringList;
  LErr, LName: string;
  LMore: Boolean;
begin
  Result := True;
  AError := '';
  LWant := TStringList.Create;
  try
    LWant.CommaText := LowerCase(StringReplace(Zones, ' ', '', [rfReplaceAll]));
    if (LWant.Count = 1) and (LWant[0] = 'all') then
      LWant.Clear;
    LDone := 0;
    LFailed := 0;
    LPage := 1;
    repeat
      R := Call('GET', Format('/zones?account.id=%s&per_page=50&page=%d', [AccountId, LPage]), '', AError, LStatus);
      if R = nil then
        Exit(False);
      try
        LMore := (R.JSONType = jtArray) and (TJSONArray(R).Count = 50);
        if R.JSONType = jtArray then
          for I := 0 to TJSONArray(R).Count - 1 do
            if TJSONArray(R).Items[I].JSONType = jtObject then
            begin
              O := TJSONObject(TJSONArray(R).Items[I]);
              LName := LowerCase(O.Get('name', ''));
              if (LWant.Count > 0) and (LWant.IndexOf(LName) < 0) then
                Continue;
              if EnsureZoneRule(O.Get('id', ''), LName, LErr) then
                Inc(LDone)
              else
              begin
                Inc(LFailed);
                Say(LErr);
              end;
            end;
      finally
        R.Free;
      end;
      Inc(LPage);
    until not LMore or (LPage > 200);
    if LDone + LFailed = 0 then
      Say('no zones to protect in the account' + BoolToStr(LWant.Count > 0, ' named in zones =', ''));
    if LFailed > 0 then
    begin
      AError := Format('%d zone(s) without the blocking rule', [LFailed]);
      Result := False;
    end
    else
      Say(Format('%d zone(s) block the list', [LDone]));
  finally
    LWant.Free;
  end;
end;

function TCloudflare.Setup: Boolean;
var
  LErr: string;
begin
  Result := FReady;
  if FReady then
    Exit;
  if DryRun then
  begin
    Say(Format('[dry-run] would use IP list %s in account %s and the rule "%s"', [ListName, AccountId,
      RuleExpression]));
    FReady := True;
    Exit(True);
  end;
  if not FindOrCreateList(LErr) then
  begin
    Say('not ready: ' + LErr);
    Exit(False);
  end;
  { a zone without the rule is logged; the list is still kept up to date }
  if MakeRules and not EnsureRules(LErr) then
    Say(LErr);
  FReady := True;
  FDirty := True;
  Result := True;
end;

procedure TCloudflare.Ban(const AIps: array of TIpAddr);
var
  I, J: Integer;
  LIp: string;
begin
  for I := 0 to High(AIps) do
  begin
    LIp := IpToStr(AIps[I]);
    J := FActive.IndexOf(LIp);
    if J >= 0 then
      FActive.Delete(J);   { banned again: now the newest }
    FActive.Add(LIp);
  end;
  { the plan's cap: the oldest bans go first }
  while FActive.Count > MaxItems do
    FActive.Delete(0);
  FDirty := True;
  Sync;
end;

procedure TCloudflare.Unban(const AIps: array of TIpAddr);
var
  I, J: Integer;
begin
  for I := 0 to High(AIps) do
  begin
    J := FActive.IndexOf(IpToStr(AIps[I]));
    if J >= 0 then
      FActive.Delete(J);
  end;
  FDirty := True;
  Sync;
end;

procedure TCloudflare.Clear;
begin
  FActive.Clear;
  FDirty := True;
  Sync;
end;

function TCloudflare.WaitForOperation(const AOpId: string; out AError: string): Boolean;
var
  R: TJSONData;
  LStatus, LTries: Integer;
  LState: string;
begin
  Result := False;
  for LTries := 1 to 120 do
  begin
    R := Call('GET', '/accounts/' + AccountId + '/rules/lists/bulk_operations/' + AOpId, '', AError, LStatus);
    if R = nil then
      Exit;
    try
      LState := '';
      if R.JSONType = jtObject then
        LState := TJSONObject(R).Get('status', '');
      if LState = 'completed' then
        Exit(True);
      if LState = 'failed' then
      begin
        AError := 'list update failed: ' + TJSONObject(R).Get('error', '');
        Exit;
      end;
    finally
      R.Free;
    end;
    Sleep(Min(250 * LTries, 2000));
  end;
  AError := 'list update still pending after the wait; the next update replaces it';
end;

function TCloudflare.Sync: Boolean;
var
  LItems: TJSONArray;
  R: TJSONData;
  LStatus, I: Integer;
  LErr, LOp: string;
begin
  Result := not FDirty;
  if not FDirty then
    Exit;
  if not Setup then
    Exit(False);
  if DryRun then
  begin
    Say(Format('[dry-run] would set list %s to %d address(es)', [ListName, FActive.Count]));
    FDirty := False;
    Exit(True);
  end;
  LItems := TJSONArray.Create;
  try
    for I := 0 to FActive.Count - 1 do
      LItems.Add(TJSONObject.Create(['ip', FActive[I]]));
    R := Call('PUT', '/accounts/' + AccountId + '/rules/lists/' + FListId + '/items', LItems.AsJSON, LErr, LStatus);
  finally
    LItems.Free;
  end;
  if R = nil then
  begin
    { the list was deleted under us: find or create it again next time }
    if LStatus = 404 then
      FReady := False;
    Say('list update failed, retried with the next ban: ' + LErr);
    Exit(False);
  end;
  try
    LOp := '';
    if R.JSONType = jtObject then
      LOp := TJSONObject(R).Get('operation_id', '');
  finally
    R.Free;
  end;
  if (LOp <> '') and not WaitForOperation(LOp, LErr) then
  begin
    Say(LErr);
    Exit(False);
  end;
  FDirty := False;
  Result := True;
end;

end.
