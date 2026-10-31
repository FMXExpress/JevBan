unit Ban.LogFormats;

(* Access logs that are not Apache's text format, read into the same
   TAccessEntry so the signatures, rules and model see the same thing whatever
   wrote the log:

   - IIS (W3C Extended): space-separated fields named by a "#Fields:" header,
     which can change at any point in a file (IIS writes a new header when it
     restarts or the logged fields change). The tailer keeps the latest header
     per file and hands it in with each line; without one, IIS's default field
     set is assumed for lines that start with a date.
   - JSON, one object per line: nginx "log_format ... escape=json", Apache
     JSON formats, Caddy, Traefik and similar. Keys are matched without regard
     to case against the names those servers use, so a hand-written log_format
     works as long as it uses the usual variable names.

   Every value is escaped as Apache escapes "%r" (ApacheEscape), so the rest of
   jevban never sees a raw quote or control byte. *)

{$mode objfpc}{$H+}

interface

uses
  SysUtils, Classes, DateUtils, fpjson, jsonparser, Ban.Net, Ban.Apache;

type
  { the columns of a W3C Extended log, from its "#Fields:" header }
  TW3CLayout = class
  public
    Count: Integer;
    IDate, ITime, IIp, IMethod, IStem, IQuery, IVersion, IStatus, IBytes, IAgent, IRef, IHost, ISite: Integer;
    constructor Create(const AFieldsLine: string);
  end;

const
  CW3CDefaultFields = '#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip ' +
    'cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken';

{ a "#Fields:" line }
function IsW3CFieldsLine(const ALine: string): Boolean;
{ any log line: JSON, W3C (ALayout, or IIS's default fields for a line that starts with a
  date), else Apache/nginx text. ALayout may be nil }
function ParseLogLine(const ALine: string; ALayout: TW3CLayout; out E: TAccessEntry): Boolean;
function ParseW3CLine(const ALine: string; ALayout: TW3CLayout; out E: TAccessEntry): Boolean;
function ParseJsonLine(const ALine: string; out E: TAccessEntry): Boolean;
{ 2026-10-31T10:00:11Z, 2026-10-31T10:00:11.123+05:30, 2026-10-31 10:00:11 -> Unix seconds UTC; 0 if not }
function ParseIsoTime(const S: string): Int64;

implementation

var
  GDefaultLayout: TW3CLayout;

function IsW3CFieldsLine(const ALine: string): Boolean;
begin
  Result := CompareText(Copy(ALine, 1, 8), '#Fields:') = 0;
end;

constructor TW3CLayout.Create(const AFieldsLine: string);
var
  LParts: TStringList;
  I: Integer;
  F: string;
begin
  inherited Create;
  IDate := -1; ITime := -1; IIp := -1; IMethod := -1; IStem := -1; IQuery := -1; IVersion := -1;
  IStatus := -1; IBytes := -1; IAgent := -1; IRef := -1; IHost := -1; ISite := -1;
  LParts := TStringList.Create;
  try
    LParts.Delimiter := ' ';
    LParts.StrictDelimiter := True;
    LParts.DelimitedText := Trim(Copy(AFieldsLine, 9, MaxInt));
    Count := 0;
    for I := 0 to LParts.Count - 1 do
    begin
      F := LowerCase(LParts[I]);
      if F = '' then
        Continue;
      if F = 'date' then IDate := Count
      else if F = 'time' then ITime := Count
      else if F = 'c-ip' then IIp := Count
      else if F = 'cs-method' then IMethod := Count
      else if F = 'cs-uri-stem' then IStem := Count
      else if F = 'cs-uri-query' then IQuery := Count
      else if F = 'cs-version' then IVersion := Count
      else if F = 'sc-status' then IStatus := Count
      else if F = 'sc-bytes' then IBytes := Count
      else if F = 'cs(user-agent)' then IAgent := Count
      else if F = 'cs(referer)' then IRef := Count
      else if F = 'cs-host' then IHost := Count
      else if F = 's-sitename' then ISite := Count;
      Inc(Count);
    end;
  finally
    LParts.Free;
  end;
end;

function TwoDigits(const S: string; AAt: Integer; out V: Integer): Boolean;
begin
  Result := (AAt + 1 <= Length(S)) and (S[AAt] in ['0'..'9']) and (S[AAt + 1] in ['0'..'9']);
  if Result then
    V := (Ord(S[AAt]) - 48) * 10 + Ord(S[AAt + 1]) - 48;
end;

function ParseIsoTime(const S: string): Int64;
var
  Y, Mo, D, H, Mi, Se, OH, OM, P: Integer;
  LSign: Integer;
begin
  Result := 0;
  if (Length(S) < 19) or (S[5] <> '-') or (S[8] <> '-') or not (S[11] in ['T', 't', ' ']) or
     (S[14] <> ':') or (S[17] <> ':') then
    Exit;
  if not TryStrToInt(Copy(S, 1, 4), Y) or not TwoDigits(S, 6, Mo) or not TwoDigits(S, 9, D) or
     not TwoDigits(S, 12, H) or not TwoDigits(S, 15, Mi) or not TwoDigits(S, 18, Se) then
    Exit;
  if (Mo < 1) or (Mo > 12) or (D < 1) or (D > 31) or (H > 23) or (Mi > 59) or (Se > 60) then
    Exit;
  try
    Result := DateTimeToUnix(EncodeDateTime(Y, Mo, D, H, Mi, Se mod 60, 0));
  except
    Exit(0);
  end;
  P := 20;
  if (P <= Length(S)) and (S[P] = '.') then
  begin
    Inc(P);
    while (P <= Length(S)) and (S[P] in ['0'..'9']) do
      Inc(P);
  end;
  { no zone: UTC (IIS, and what a "Z"-less ISO time from a log almost always means) }
  if (P <= Length(S)) and (S[P] in ['+', '-']) then
  begin
    if S[P] = '-' then LSign := -1 else LSign := 1;
    if TwoDigits(S, P + 1, OH) then
    begin
      OM := 0;
      if (P + 3 <= Length(S)) and (S[P + 3] = ':') then
        TwoDigits(S, P + 4, OM)
      else
        TwoDigits(S, P + 3, OM);
      Result := Result - LSign * (OH * 3600 + OM * 60);
    end;
  end;
end;

function Dash(const S: string): string;
begin
  if S = '-' then
    Result := ''
  else
    Result := S;
end;

function ParseW3CLine(const ALine: string; ALayout: TW3CLayout; out E: TAccessEntry): Boolean;
var
  V: array of string;
  N, P, LStart: Integer;
  LTarget, LQuery, LVersion: string;

  function Field(AIdx: Integer): string;
  begin
    if (AIdx >= 0) and (AIdx < N) then
      Result := Dash(V[AIdx])
    else
      Result := '';
  end;

begin
  Result := False;
  E := Default(TAccessEntry);
  if (ALayout = nil) or (ALayout.IIp < 0) or (ALayout.IStem < 0) then
    Exit;
  SetLength(V, ALayout.Count);
  N := 0;
  P := 1;
  while (P <= Length(ALine)) and (N < ALayout.Count) do
  begin
    LStart := P;
    while (P <= Length(ALine)) and (ALine[P] <> ' ') do
      Inc(P);
    V[N] := Copy(ALine, LStart, P - LStart);
    Inc(N);
    Inc(P);
  end;
  if N <> ALayout.Count then
    Exit;
  if not ParseIp(Field(ALayout.IIp), E.Ip) then
    Exit;
  E.IpText := IpToStr(E.Ip);
  E.Epoch := ParseIsoTime(Field(ALayout.IDate) + 'T' + Field(ALayout.ITime));
  E.TimeText := FormatApacheTime(E.Epoch);
  E.Status := StrToIntDef(Field(ALayout.IStatus), 0);
  E.Bytes := StrToInt64Def(Field(ALayout.IBytes), 0);
  { IIS writes a space in these as "+" }
  E.Agent := ApacheEscape(StringReplace(Field(ALayout.IAgent), '+', ' ', [rfReplaceAll]));
  E.Referer := ApacheEscape(Field(ALayout.IRef));
  if ALayout.IHost >= 0 then
    E.VHost := Field(ALayout.IHost)
  else
    E.VHost := Field(ALayout.ISite);
  LTarget := Field(ALayout.IStem);
  LQuery := Field(ALayout.IQuery);
  if LQuery <> '' then
    LTarget := LTarget + '?' + LQuery;
  LVersion := Field(ALayout.IVersion);
  if LVersion = '' then
    LVersion := 'HTTP/1.1';
  E.Request := ApacheEscape(Field(ALayout.IMethod) + ' ' + LTarget + ' ' + LVersion);
  SplitRequest(E);
  Result := True;
end;

{ JSON }

function FindKey(AObj: TJSONObject; const ANames: array of string): TJSONData;
var
  I, J: Integer;
begin
  for J := Low(ANames) to High(ANames) do
    for I := 0 to AObj.Count - 1 do
      if CompareText(AObj.Names[I], ANames[J]) = 0 then
        Exit(AObj.Items[I]);
  Result := nil;
end;

function KeyText(AObj: TJSONObject; const ANames: array of string): string;
var
  D: TJSONData;
begin
  D := FindKey(AObj, ANames);
  if D = nil then
    Exit('');
  if D.JSONType = jtArray then
  begin
    { Caddy logs headers as arrays: "User-Agent": ["curl/8"] }
    if TJSONArray(D).Count = 0 then
      Exit('');
    D := TJSONArray(D).Items[0];
  end;
  if D.JSONType in [jtString, jtNumber, jtBoolean] then
    Result := Dash(D.AsString)
  else
    Result := '';
end;

function JsonTime(AObj: TJSONObject): Int64;
var
  D: TJSONData;
  S: string;
  F: Double;
begin
  Result := 0;
  D := FindKey(AObj, ['time_local', 'time_iso8601', 'timestamp', '@timestamp', 'time', 'ts', 'msec',
    'startutc', 'start_utc', 'datetime', 'date']);
  if D = nil then
    Exit;
  if D.JSONType = jtNumber then
    F := D.AsFloat
  else
  begin
    S := D.AsString;
    if (S <> '') and (S[1] in ['0'..'9']) and (Pos('/', S) = 0) and (Pos('-', S) = 0) and
       TryStrToFloat(S, F, DefaultFormatSettings) then
      { nginx $msec: "1730368811.123" }
    else
    begin
      if Pos('/', S) > 0 then
        Exit(ParseApacheTime('[' + S + ']'));
      Exit(ParseIsoTime(S));
    end;
  end;
  if F > 1e12 then
    F := F / 1000;   { milliseconds }
  Result := Trunc(F);
end;

function ParseJsonLine(const ALine: string; out E: TAccessEntry): Boolean;
var
  LData: TJSONData;
  O, LReq, LHeaders: TJSONObject;
  LIp, LMethod, LUri, LQuery, LProto, LRequest: string;
begin
  Result := False;
  E := Default(TAccessEntry);
  try
    LData := GetJSON(ALine);
  except
    Exit;
  end;
  try
    if (LData = nil) or (LData.JSONType <> jtObject) then
      Exit;
    O := TJSONObject(LData);
    (* Caddy nests the request: {"request": {"remote_ip", "method", "uri", "proto", "headers"}, "status", "size", "ts"} *)
    LReq := nil;
    LHeaders := nil;
    if (FindKey(O, ['request']) <> nil) and (FindKey(O, ['request']).JSONType = jtObject) then
    begin
      LReq := TJSONObject(FindKey(O, ['request']));
      if (FindKey(LReq, ['headers']) <> nil) and (FindKey(LReq, ['headers']).JSONType = jtObject) then
        LHeaders := TJSONObject(FindKey(LReq, ['headers']));
    end;
    LIp := KeyText(O, ['remote_addr', 'client_ip', 'clientip', 'remote_ip', 'c-ip', 'clienthost', 'client_host',
      'ip', 'client', 'remote_host', 'remotehost', 'clientaddr']);
    if (LIp = '') and (LReq <> nil) then
      LIp := KeyText(LReq, ['client_ip', 'remote_ip', 'remote_addr']);
    { "ip:port" from a few loggers (Traefik ClientAddr, Caddy remote_addr) }
    if not ParseIp(LIp, E.Ip) then
    begin
      if (LIp <> '') and (LIp[1] = '[') and (Pos(']', LIp) > 0) then
        LIp := Copy(LIp, 2, Pos(']', LIp) - 2)
      else if (Pos(':', LIp) > 0) and (Pos(':', LIp) = LastDelimiter(':', LIp)) then
        LIp := Copy(LIp, 1, Pos(':', LIp) - 1);
      if not ParseIp(LIp, E.Ip) then
        Exit;
    end;
    E.IpText := IpToStr(E.Ip);
    E.Epoch := JsonTime(O);
    E.TimeText := FormatApacheTime(E.Epoch);
    E.Status := StrToIntDef(KeyText(O, ['status', 'downstreamstatus', 'response_status', 'status_code',
      'sc-status']), 0);
    E.Bytes := StrToInt64Def(KeyText(O, ['body_bytes_sent', 'bytes_sent', 'bytes', 'size',
      'downstreamcontentsize', 'response_size', 'sc-bytes']), 0);
    E.Agent := KeyText(O, ['http_user_agent', 'user_agent', 'useragent', 'agent', 'ua', 'request_user-agent']);
    E.Referer := KeyText(O, ['http_referer', 'referer', 'referrer', 'request_referer']);
    if LHeaders <> nil then
    begin
      if E.Agent = '' then
        E.Agent := KeyText(LHeaders, ['user-agent']);
      if E.Referer = '' then
        E.Referer := KeyText(LHeaders, ['referer']);
    end;
    E.Agent := ApacheEscape(E.Agent);
    E.Referer := ApacheEscape(E.Referer);
    E.VHost := KeyText(O, ['host', 'http_host', 'server_name', 'vhost', 'requesthost']);
    if (E.VHost = '') and (LReq <> nil) then
      E.VHost := KeyText(LReq, ['host']);
    { the request line, or its parts }
    LRequest := '';
    if (LReq = nil) then
      LRequest := KeyText(O, ['request', 'request_line', 'requestline']);
    if LRequest = '' then
    begin
      LMethod := KeyText(O, ['request_method', 'method', 'requestmethod', 'cs-method']);
      LUri := KeyText(O, ['request_uri', 'uri', 'requestpath', 'path', 'url', 'cs-uri-stem']);
      LProto := KeyText(O, ['server_protocol', 'protocol', 'requestprotocol', 'proto']);
      if LReq <> nil then
      begin
        if LMethod = '' then LMethod := KeyText(LReq, ['method']);
        if LUri = '' then LUri := KeyText(LReq, ['uri']);
        if LProto = '' then LProto := KeyText(LReq, ['proto']);
      end;
      if LUri = '' then
        Exit;
      { $uri has no query; $args (or query_string) carries it. $request_uri has both }
      if Pos('?', LUri) = 0 then
      begin
        LQuery := KeyText(O, ['args', 'query_string', 'query', 'cs-uri-query']);
        if LQuery <> '' then
          LUri := LUri + '?' + LQuery;
      end;
      if LMethod = '' then
        LMethod := 'GET';
      LRequest := LMethod + ' ' + LUri;
      if LProto <> '' then
        LRequest := LRequest + ' ' + LProto;
    end;
    E.Request := ApacheEscape(LRequest);
    SplitRequest(E);
    Result := True;
  finally
    LData.Free;
  end;
end;

function LooksLikeW3CDate(const ALine: string): Boolean;
begin
  Result := (Length(ALine) > 20) and (ALine[5] = '-') and (ALine[8] = '-') and (ALine[11] = ' ') and
    (ALine[1] in ['1', '2']) and (ALine[14] = ':');
end;

function ParseLogLine(const ALine: string; ALayout: TW3CLayout; out E: TAccessEntry): Boolean;
begin
  if (ALine <> '') and (ALine[1] = '{') then
    Exit(ParseJsonLine(ALine, E));
  if ALayout <> nil then
    Exit(ParseW3CLine(ALine, ALayout, E));
  if LooksLikeW3CDate(ALine) then
    Exit(ParseW3CLine(ALine, GDefaultLayout, E));
  Result := ParseAccessLine(ALine, E);
end;

initialization
  GDefaultLayout := TW3CLayout.Create(CW3CDefaultFields);
finalization
  GDefaultLayout.Free;
end.
