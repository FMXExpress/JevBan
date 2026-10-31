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
{ for the tests: the JSON node list by the fast scanner and by fpjson, one node per line; '' if it fails }
function JsonNodesFast(const ALine: string): string;
function JsonNodesTree(const ALine: string): string;

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

(* A JSON line as a flat list of nodes in document order: key, kind, text and
   the index of the containing object or array (the root object is node 0).
   The access log needs a few scalars from one or two levels, so a node list
   is all it takes: no tree of objects per line. *)
type
  TJNode = record
    Key: string;
    Kind: Char;      { s string, n number, b boolean, z null, o object, a array }
    Text: string;    { a scalar's value as fpjson's AsString gives it }
    Parent: Integer;
  end;

  TJDoc = record
    Nodes: array of TJNode;
    Count: Integer;
  end;

function JAdd(var D: TJDoc; const AKey: string; AKind: Char; const AText: string; AParent: Integer): Integer;
begin
  if D.Count = Length(D.Nodes) then
    SetLength(D.Nodes, D.Count * 2 + 16);
  D.Nodes[D.Count].Key := AKey;
  D.Nodes[D.Count].Kind := AKind;
  D.Nodes[D.Count].Text := AText;
  D.Nodes[D.Count].Parent := AParent;
  Result := D.Count;
  Inc(D.Count);
end;

(* the fast scanner: one pass, no allocation but the node strings. Anything it
   does not handle exactly as fpjson would (escapes beyond \u00xx-߿ and
   the BMP, a duplicate key, deep nesting, trailing text) makes it give up, and
   the line goes to fpjson instead *)
function JScan(const S: string; var D: TJDoc): Boolean;
var
  P, N: Integer;

  procedure Ws; inline;
  begin
    while (P <= N) and (S[P] in [' ', #9, #10, #13]) do
      Inc(P);
  end;

  function Hex4(out V: Integer): Boolean;
  var
    I, H: Integer;
  begin
    V := 0;
    if P + 3 > N then
      Exit(False);
    for I := 0 to 3 do
    begin
      case S[P + I] of
        '0'..'9': H := Ord(S[P + I]) - 48;
        'a'..'f': H := Ord(S[P + I]) - 87;
        'A'..'F': H := Ord(S[P + I]) - 55;
      else
        Exit(False);
      end;
      V := V * 16 + H;
    end;
    Inc(P, 4);
    Result := True;
  end;

  function Str(out T: string): Boolean;
  var
    LStart, V: Integer;
  begin
    Result := False;
    Inc(P);   { the opening quote }
    LStart := P;
    while (P <= N) and (S[P] <> '"') and (S[P] <> '\') and (S[P] >= ' ') do
      Inc(P);
    if P > N then
      Exit;
    T := Copy(S, LStart, P - LStart);
    while P <= N do
      case S[P] of
        '"':
          begin
            Inc(P);
            Exit(True);
          end;
        '\':
          begin
            Inc(P);
            if P > N then
              Exit;
            case S[P] of
              '"', '\', '/': T := T + S[P];
              'b': T := T + #8;
              'f': T := T + #12;
              'n': T := T + #10;
              'r': T := T + #13;
              't': T := T + #9;
              'u':
                begin
                  Inc(P);
                  if not Hex4(V) then
                    Exit;
                  { UTF-8 as fpjson writes it; surrogates are left to fpjson }
                  if V < $80 then
                    T := T + Chr(V)
                  else if V < $800 then
                    T := T + Chr($C0 or (V shr 6)) + Chr($80 or (V and $3F))
                  else if (V >= $D800) and (V <= $DFFF) then
                    Exit
                  else
                    T := T + Chr($E0 or (V shr 12)) + Chr($80 or ((V shr 6) and $3F)) + Chr($80 or (V and $3F));
                  Continue;
                end;
            else
              Exit;
            end;
            Inc(P);
          end;
      else
        if S[P] < ' ' then
          Exit;   { a raw control character: not JSON }
        T := T + S[P];
        Inc(P);
      end;
    Result := False;
  end;

  function Value(const AKey: string; AParent, ADepth: Integer): Boolean; forward;

  function Obj(const AKey: string; AParent, ADepth: Integer): Boolean;
  var
    LMe, I: Integer;
    LKey: string;
  begin
    Result := False;
    LMe := JAdd(D, AKey, 'o', '', AParent);
    Inc(P);   { the brace }
    Ws;
    if (P <= N) and (S[P] = '}') then
    begin
      Inc(P);
      Exit(True);
    end;
    repeat
      Ws;
      if (P > N) or (S[P] <> '"') or not Str(LKey) then
        Exit;
      { fpjson rejects a key twice in one object }
      for I := LMe + 1 to D.Count - 1 do
        if (D.Nodes[I].Parent = LMe) and (D.Nodes[I].Key = LKey) then
          Exit;
      Ws;
      if (P > N) or (S[P] <> ':') then
        Exit;
      Inc(P);
      Ws;
      if not Value(LKey, LMe, ADepth + 1) then
        Exit;
      Ws;
      if P > N then
        Exit;
      if S[P] = ',' then
        Inc(P)
      else if S[P] = '}' then
      begin
        Inc(P);
        Exit(True);
      end
      else
        Exit;
    until False;
  end;

  function Arr(const AKey: string; AParent, ADepth: Integer): Boolean;
  var
    LMe: Integer;
  begin
    Result := False;
    LMe := JAdd(D, AKey, 'a', '', AParent);
    Inc(P);
    Ws;
    if (P <= N) and (S[P] = ']') then
    begin
      Inc(P);
      Exit(True);
    end;
    repeat
      Ws;
      if not Value('', LMe, ADepth + 1) then
        Exit;
      Ws;
      if P > N then
        Exit;
      if S[P] = ',' then
        Inc(P)
      else if S[P] = ']' then
      begin
        Inc(P);
        Exit(True);
      end
      else
        Exit;
    until False;
  end;

  function Value(const AKey: string; AParent, ADepth: Integer): Boolean;
  var
    LStart, I: Integer;
    T: string;
  begin
    Result := False;
    if (P > N) or (ADepth > 16) then
      Exit;
    case S[P] of
      '{': Result := Obj(AKey, AParent, ADepth);
      '[': Result := Arr(AKey, AParent, ADepth);
      '"':
        begin
          if not Str(T) then
            Exit;
          JAdd(D, AKey, 's', T, AParent);
          Result := True;
        end;
      '-', '0'..'9':
        begin
          LStart := P;
          Inc(P);
          while (P <= N) and (S[P] in ['0'..'9']) do
            Inc(P);
          if (P - LStart > 18) or ((S[LStart] = '-') and (P - LStart = 1)) then
            Exit;
          { -0 and leading zeros: fpjson prints them otherwise }
          if S[LStart] = '-' then
            I := LStart + 1
          else
            I := LStart;
          if (S[I] = '0') and (P - I > 1) then
            Exit;
          (* a fraction or exponent (Caddy's "ts": 1793440815.25) is kept as
             written: its readers take it with TryStrToFloat, which gives the
             same value as from fpjson's printing, or StrToIntDef, which fails
             on both *)
          if (P <= N) and (S[P] = '.') then
          begin
            Inc(P);
            if (P > N) or not (S[P] in ['0'..'9']) then
              Exit;
            while (P <= N) and (S[P] in ['0'..'9']) do
              Inc(P);
          end;
          if (P <= N) and (S[P] in ['e', 'E']) then
          begin
            Inc(P);
            if (P <= N) and (S[P] in ['+', '-']) then
              Inc(P);
            if (P > N) or not (S[P] in ['0'..'9']) then
              Exit;
            while (P <= N) and (S[P] in ['0'..'9']) do
              Inc(P);
          end;
          if Copy(S, LStart, P - LStart) = '-0' then
            Exit;
          JAdd(D, AKey, 'n', Copy(S, LStart, P - LStart), AParent);
          Result := True;
        end;
      't':
        if Copy(S, P, 4) = 'true' then
        begin
          Inc(P, 4);
          JAdd(D, AKey, 'b', 'True', AParent);
          Result := True;
        end;
      'f':
        if Copy(S, P, 5) = 'false' then
        begin
          Inc(P, 5);
          JAdd(D, AKey, 'b', 'False', AParent);
          Result := True;
        end;
      'n':
        if Copy(S, P, 4) = 'null' then
        begin
          Inc(P, 4);
          JAdd(D, AKey, 'z', '', AParent);
          Result := True;
        end;
    end;
  end;

begin
  D.Count := 0;
  N := Length(S);
  P := 1;
  Ws;
  if (P > N) or (S[P] <> '{') then
    Exit(False);
  Result := Obj('', -1, 0);
  if Result then
  begin
    Ws;
    Result := P > N;
  end;
end;

{ the same node list from fpjson's tree: for the lines the scanner leaves to it }
procedure JFromTree(AData: TJSONData; const AKey: string; AParent: Integer; var D: TJDoc);
var
  I, LMe: Integer;
begin
  case AData.JSONType of
    jtObject:
      begin
        LMe := JAdd(D, AKey, 'o', '', AParent);
        for I := 0 to TJSONObject(AData).Count - 1 do
          JFromTree(TJSONObject(AData).Items[I], TJSONObject(AData).Names[I], LMe, D);
      end;
    jtArray:
      begin
        LMe := JAdd(D, AKey, 'a', '', AParent);
        for I := 0 to TJSONArray(AData).Count - 1 do
          JFromTree(TJSONArray(AData).Items[I], '', LMe, D);
      end;
    jtString: JAdd(D, AKey, 's', AData.AsString, AParent);
    jtNumber: JAdd(D, AKey, 'n', AData.AsString, AParent);
    jtBoolean: JAdd(D, AKey, 'b', AData.AsString, AParent);
  else
    JAdd(D, AKey, 'z', '', AParent);
  end;
end;

function JParse(const ALine: string; var D: TJDoc): Boolean;
var
  LData: TJSONData;
begin
  if JScan(ALine, D) then
    Exit(True);
  D.Count := 0;
  try
    LData := GetJSON(ALine);
  except
    Exit(False);
  end;
  try
    Result := (LData <> nil) and (LData.JSONType = jtObject);
    if Result then
      JFromTree(LData, '', -1, D);
  finally
    LData.Free;
  end;
end;

{ the first child of AObj named any of ANames (in the order of ANames), -1 if none }
function JFind(const D: TJDoc; AObj: Integer; const ANames: array of string): Integer;
var
  I, J: Integer;
begin
  if AObj < 0 then
    Exit(-1);
  for J := Low(ANames) to High(ANames) do
    for I := AObj + 1 to D.Count - 1 do
      if (D.Nodes[I].Parent = AObj) and (CompareText(D.Nodes[I].Key, ANames[J]) = 0) then
        Exit(I);
  Result := -1;
end;

function JObj(const D: TJDoc; AObj: Integer; const AName: string): Integer;
begin
  Result := JFind(D, AObj, [AName]);
  if (Result >= 0) and (D.Nodes[Result].Kind <> 'o') then
    Result := -1;
end;

function KeyText(const D: TJDoc; AObj: Integer; const ANames: array of string): string;
var
  I, K: Integer;
begin
  Result := '';
  K := JFind(D, AObj, ANames);
  if K < 0 then
    Exit;
  if D.Nodes[K].Kind = 'a' then
  begin
    { Caddy logs headers as arrays: "User-Agent": ["curl/8"] }
    I := K + 1;
    while (I < D.Count) and (D.Nodes[I].Parent <> K) do
      Inc(I);
    if I >= D.Count then
      Exit;
    K := I;
  end;
  if D.Nodes[K].Kind in ['s', 'n', 'b'] then
    Result := Dash(D.Nodes[K].Text);
end;

function JsonTime(const D: TJDoc): Int64;
var
  K: Integer;
  S: string;
  F: Double;
begin
  Result := 0;
  K := JFind(D, 0, ['time_local', 'time_iso8601', 'timestamp', '@timestamp', 'time', 'ts', 'msec',
    'startutc', 'start_utc', 'datetime', 'date']);
  if K < 0 then
    Exit;
  S := D.Nodes[K].Text;
  if D.Nodes[K].Kind = 'n' then
  begin
    if not TryStrToFloat(S, F, DefaultFormatSettings) then
      Exit;
  end
  else
  begin
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

threadvar
  GDoc: TJDoc;   { reused: its node strings and array grow once }

function ParseJsonLine(const ALine: string; out E: TAccessEntry): Boolean;
var
  LReq, LHeaders: Integer;
  LIp, LMethod, LUri, LQuery, LProto, LRequest: string;
begin
  Result := False;
  E := Default(TAccessEntry);
  if not JParse(ALine, GDoc) then
    Exit;
  (* Caddy nests the request: {"request": {"remote_ip", "method", "uri", "proto", "headers"}, "status", "size", "ts"} *)
  LReq := JObj(GDoc, 0, 'request');
  LHeaders := JObj(GDoc, LReq, 'headers');
  LIp := KeyText(GDoc, 0, ['remote_addr', 'client_ip', 'clientip', 'remote_ip', 'c-ip', 'clienthost', 'client_host',
    'ip', 'client', 'remote_host', 'remotehost', 'clientaddr']);
  if (LIp = '') and (LReq >= 0) then
    LIp := KeyText(GDoc, LReq, ['client_ip', 'remote_ip', 'remote_addr']);
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
  E.Epoch := JsonTime(GDoc);
  E.TimeText := FormatApacheTime(E.Epoch);
  E.Status := StrToIntDef(KeyText(GDoc, 0, ['status', 'downstreamstatus', 'response_status', 'status_code',
    'sc-status']), 0);
  E.Bytes := StrToInt64Def(KeyText(GDoc, 0, ['body_bytes_sent', 'bytes_sent', 'bytes', 'size',
    'downstreamcontentsize', 'response_size', 'sc-bytes']), 0);
  E.Agent := KeyText(GDoc, 0, ['http_user_agent', 'user_agent', 'useragent', 'agent', 'ua', 'request_user-agent']);
  E.Referer := KeyText(GDoc, 0, ['http_referer', 'referer', 'referrer', 'request_referer']);
  if LHeaders >= 0 then
  begin
    if E.Agent = '' then
      E.Agent := KeyText(GDoc, LHeaders, ['user-agent']);
    if E.Referer = '' then
      E.Referer := KeyText(GDoc, LHeaders, ['referer']);
  end;
  E.Agent := ApacheEscape(E.Agent);
  E.Referer := ApacheEscape(E.Referer);
  E.VHost := KeyText(GDoc, 0, ['host', 'http_host', 'server_name', 'vhost', 'requesthost']);
  if (E.VHost = '') and (LReq >= 0) then
    E.VHost := KeyText(GDoc, LReq, ['host']);
  { the request line, or its parts }
  LRequest := '';
  if LReq < 0 then
    LRequest := KeyText(GDoc, 0, ['request', 'request_line', 'requestline']);
  if LRequest = '' then
  begin
    LMethod := KeyText(GDoc, 0, ['request_method', 'method', 'requestmethod', 'cs-method']);
    LUri := KeyText(GDoc, 0, ['request_uri', 'uri', 'requestpath', 'path', 'url', 'cs-uri-stem']);
    LProto := KeyText(GDoc, 0, ['server_protocol', 'protocol', 'requestprotocol', 'proto']);
    if LReq >= 0 then
    begin
      if LMethod = '' then LMethod := KeyText(GDoc, LReq, ['method']);
      if LUri = '' then LUri := KeyText(GDoc, LReq, ['uri']);
      if LProto = '' then LProto := KeyText(GDoc, LReq, ['proto']);
    end;
    if LUri = '' then
      Exit;
    { $uri has no query; $args (or query_string) carries it. $request_uri has both }
    if Pos('?', LUri) = 0 then
    begin
      LQuery := KeyText(GDoc, 0, ['args', 'query_string', 'query', 'cs-uri-query']);
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
end;

function JDump(const D: TJDoc): string;
var
  I: Integer;
  LText: string;
  F: Double;
begin
  Result := '';
  for I := 0 to D.Count - 1 do
  begin
    LText := D.Nodes[I].Text;
    { a number by its value: the scanner keeps it as written, fpjson prints a float its own way }
    if (D.Nodes[I].Kind = 'n') and TryStrToFloat(LText, F, DefaultFormatSettings) then
      LText := FloatToStr(F, DefaultFormatSettings) + ' ' + IntToStr(StrToIntDef(LText, -1));
    Result := Result + Format('%d|%s|%s|%s' + #10, [D.Nodes[I].Parent, D.Nodes[I].Key, D.Nodes[I].Kind, LText]);
  end;
end;

function JsonNodesFast(const ALine: string): string;
var
  D: TJDoc;
begin
  D := Default(TJDoc);
  if JScan(ALine, D) then
    Result := JDump(D)
  else
    Result := '';
end;

function JsonNodesTree(const ALine: string): string;
var
  D: TJDoc;
  LData: TJSONData;
begin
  Result := '';
  D := Default(TJDoc);
  try
    LData := GetJSON(ALine);
  except
    Exit;
  end;
  try
    if (LData <> nil) and (LData.JSONType = jtObject) then
    begin
      JFromTree(LData, '', -1, D);
      Result := JDump(D);
    end;
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
