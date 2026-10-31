unit Ban.Apache;

(* Apache access log lines: common, combined and vhost_combined
     [%v:%p ]%h %l %u %t "%r" %>s %b[ "%{Referer}i" "%{User-Agent}i"]
   (nginx's default "combined" is the same shape). The bracketed time field
   anchors the parse: the client address is the third token before it, so an
   optional vhost prefix needs no configuration. Apache escapes quotes and
   non-printable bytes in "%r" as \" and \xhh; Request keeps that escaped
   text (safe to log and to show a model), Decoded is what the attacker
   actually sent, URL-decoded, for the signatures. *)

{$mode objfpc}{$H+}

interface

uses
  SysUtils, Classes, DateUtils, Ban.Net;

type
  TAccessEntry = record
    VHost: string;
    Ip: TIpAddr;
    IpText: string;     { canonical (IpToStr) }
    TimeText: string;
    Epoch: Int64;       { the log time, Unix seconds UTC; 0 if unparsable }
    Request: string;    { "%r" as logged, Apache-escaped }
    Method, Target, Protocol: string;
    Decoded: string;    { Target with \xhh and %hh (twice) undone }
    Status: Integer;
    Bytes: Int64;
    Referer, Agent: string;
  end;

function ParseAccessLine(const ALine: string; out E: TAccessEntry): Boolean;
{ one line for a model or a log: time, request, status, size, agent }
function EntrySummary(const E: TAccessEntry; AMaxLen: Integer = 400): string;
(* the request as the decider sees it: time of day, request, status, size, and the
   referer and user agent only when they say something (the client's usual user
   agent is stated once for the client, not on every line) *)
function CompactSummary(const E: TAccessEntry; const AClientAgent: string; AMaxLen: Integer = 300): string;
function ApacheUnescape(const S: string): string;
function UrlDecode(const S: string): string;
function UnixNow: Int64;
{ [10/Oct/2000:13:55:36 -0700] -> Unix seconds UTC; 0 if unparsable }
function ParseApacheTime(const S: string): Int64;
{ Unix seconds -> [10/Oct/2000:20:55:36 +0000], the TimeText every format fills in }
function FormatApacheTime(AEpoch: Int64): string;
{ escapes a raw value the way Apache logs "%r": \" \\ and \xhh for control and non-ASCII bytes }
function ApacheEscape(const S: string): string;
{ splits "METHOD target PROTOCOL" into E.Method, E.Target, E.Protocol and sets E.Decoded }
procedure SplitRequest(var E: TAccessEntry);

implementation

function UnixNow: Int64;
begin
  Result := DateTimeToUnix(LocalTimeToUniversal(Now));
end;

function ApacheUnescape(const S: string): string;
var
  I, LHi, LLo: Integer;

  function Hex(C: Char): Integer;
  begin
    case C of
      '0'..'9': Result := Ord(C) - 48;
      'a'..'f': Result := Ord(C) - 87;
      'A'..'F': Result := Ord(C) - 55;
    else
      Result := -1;
    end;
  end;

begin
  if Pos('\', S) = 0 then
    Exit(S);
  Result := '';
  I := 1;
  while I <= Length(S) do
  begin
    if (S[I] = '\') and (I < Length(S)) then
    begin
      if (S[I + 1] = 'x') and (I + 3 <= Length(S)) then
      begin
        LHi := Hex(S[I + 2]);
        LLo := Hex(S[I + 3]);
        if (LHi >= 0) and (LLo >= 0) then
        begin
          Result := Result + Chr(LHi * 16 + LLo);
          Inc(I, 4);
          Continue;
        end;
      end;
      case S[I + 1] of
        '"', '\': Result := Result + S[I + 1];
        'n': Result := Result + #10;
        'r': Result := Result + #13;
        't': Result := Result + #9;
      else
        Result := Result + S[I] + S[I + 1];
      end;
      Inc(I, 2);
      Continue;
    end;
    Result := Result + S[I];
    Inc(I);
  end;
end;

function UrlDecode(const S: string): string;
var
  I, N, LVal: Integer;
begin
  if (Pos('%', S) = 0) and (Pos('+', S) = 0) then
    Exit(S);
  { decoding only ever shortens: write in place, trim at the end }
  SetLength(Result, Length(S));
  N := 0;
  I := 1;
  while I <= Length(S) do
  begin
    Inc(N);
    if (S[I] = '%') and (I + 2 <= Length(S)) and
       TryStrToInt('$' + Copy(S, I + 1, 2), LVal) then
    begin
      Result[N] := Chr(LVal);
      Inc(I, 3);
      Continue;
    end;
    if S[I] = '+' then
      Result[N] := ' '
    else
      Result[N] := S[I];
    Inc(I);
  end;
  SetLength(Result, N);
end;

const
  CMonths: array[1..12] of string = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
    'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec');

{ [10/Oct/2000:13:55:36 -0700] }
threadvar
  { log lines come in time order: most share the previous line's second }
  GLastTimeText: string;
  GLastTime: Int64;

function ParseApacheTimeUncached(const S: string): Int64; forward;

function ParseApacheTime(const S: string): Int64;
begin
  if S = GLastTimeText then
    Exit(GLastTime);
  Result := ParseApacheTimeUncached(S);
  GLastTimeText := S;
  GLastTime := Result;
end;

function ParseApacheTimeUncached(const S: string): Int64;
var
  LDay, LMon, LYear, LHour, LMin, LSec, LOff, I: Integer;
  LText: string;
begin
  Result := 0;
  LText := Copy(S, 2, Length(S) - 2);
  if Length(LText) < 26 then
    Exit;
  LMon := 0;
  for I := 1 to 12 do
    if CMonths[I] = Copy(LText, 4, 3) then
      LMon := I;
  if (LMon = 0) or
     not TryStrToInt(Copy(LText, 1, 2), LDay) or
     not TryStrToInt(Copy(LText, 8, 4), LYear) or
     not TryStrToInt(Copy(LText, 13, 2), LHour) or
     not TryStrToInt(Copy(LText, 16, 2), LMin) or
     not TryStrToInt(Copy(LText, 19, 2), LSec) or
     not TryStrToInt(Copy(LText, 22, 5), LOff) then
    Exit;
  if (LDay < 1) or (LDay > 31) or (LHour > 23) or (LMin > 59) or (LSec > 60) then
    Exit;
  try
    Result := DateTimeToUnix(EncodeDateTime(LYear, LMon, LDay, LHour, LMin, LSec mod 60, 0));
  except
    Exit(0);
  end;
  { local = UTC + offset; -0530 parses as -530: div and mod keep the sign }
  LOff := (LOff div 100) * 3600 + (LOff mod 100) * 60;
  Result := Result - LOff;
end;

threadvar
  GLastFmtEpoch: Int64;
  GLastFmtText: string;

function FormatApacheTimeUncached(AEpoch: Int64): string; forward;

function FormatApacheTime(AEpoch: Int64): string;
begin
  { lines come in time order: most share the previous line's second }
  if (GLastFmtText <> '') and (AEpoch = GLastFmtEpoch) then
    Exit(GLastFmtText);
  Result := FormatApacheTimeUncached(AEpoch);
  GLastFmtEpoch := AEpoch;
  GLastFmtText := Result;
end;

function FormatApacheTimeUncached(AEpoch: Int64): string;
var
  D: TDateTime;
  Y, M, Dd, H, N, Sec, Ms: Word;
begin
  D := UnixToDateTime(AEpoch);
  DecodeDateTime(D, Y, M, Dd, H, N, Sec, Ms);
  Result := Format('[%.2d/%s/%.4d:%.2d:%.2d:%.2d +0000]', [Dd, CMonths[M], Y, H, N, Sec]);
end;

function ApacheEscape(const S: string): string;
const
  CHex: array[0..15] of Char = '0123456789abcdef';
var
  I, N: Integer;
  C: Char;
begin
  { nearly always nothing to escape: the string itself, no copy }
  I := 1;
  while (I <= Length(S)) and (S[I] in [#32..#33, #35..#91, #93..#126]) do
    Inc(I);
  if I > Length(S) then
    Exit(S);
  { at most four characters for one: write in place, trim at the end }
  SetLength(Result, Length(S) * 4);
  N := 0;
  for I := 1 to Length(S) do
  begin
    C := S[I];
    case C of
      '"', '\':
        begin
          Result[N + 1] := '\';
          Result[N + 2] := C;
          Inc(N, 2);
        end;
      #32..#33, #35..#91, #93..#126:
        begin
          Result[N + 1] := C;
          Inc(N);
        end;
    else
      Result[N + 1] := '\';
      Result[N + 2] := 'x';
      Result[N + 3] := CHex[Ord(C) shr 4];
      Result[N + 4] := CHex[Ord(C) and 15];
      Inc(N, 4);
    end;
  end;
  SetLength(Result, N);
end;

type
  { a token's place in the line: its text is copied only if the parser uses it }
  TSpan = record
    Start, Len: Integer;
    Kind: Char;   { '"' quoted (Start/Len: inside the quotes), '[' bracketed (with the brackets), ' ' plain }
  end;

{ next token: "quoted" (escapes kept), [bracketed], or up to a space; as NextToken }
function NextSpan(const L: string; var P: Integer; out T: TSpan): Boolean;
var
  N: Integer;
begin
  N := Length(L);
  while (P <= N) and (L[P] = ' ') do
    Inc(P);
  if P > N then
    Exit(False);
  Result := True;
  if L[P] = '"' then
  begin
    Inc(P);
    T.Start := P;
    while (P <= N) and (L[P] <> '"') do
    begin
      if (L[P] = '\') and (P < N) then
        Inc(P);
      Inc(P);
    end;
    T.Len := P - T.Start;
    T.Kind := '"';
    Inc(P);
  end
  else if L[P] = '[' then
  begin
    T.Start := P;
    while (P <= N) and (L[P] <> ']') do
      Inc(P);
    T.Len := P - T.Start + 1;
    T.Kind := '[';
    Inc(P);
  end
  else
  begin
    T.Start := P;
    while (P <= N) and (L[P] <> ' ') do
      Inc(P);
    T.Len := P - T.Start;
    T.Kind := ' ';
  end;
end;

function ParseAccessLine(const ALine: string; out E: TAccessEntry): Boolean;
var
  LTok: array[0..15] of TSpan;
  P, LTime, N: Integer;

  { the token's text; a quoted one without its quotes (what Unquote gave) }
  function Text(AIdx: Integer): string; inline;
  begin
    Result := Copy(ALine, LTok[AIdx].Start, LTok[AIdx].Len);
  end;

  { the token as NextToken returned it: a quoted one keeps its opening quote }
  function Raw(AIdx: Integer): string;
  begin
    Result := Text(AIdx);
    if LTok[AIdx].Kind = '"' then
      Result := '"' + Result;
  end;

begin
  Result := False;
  E := Default(TAccessEntry);
  P := 1;
  LTime := -1;
  N := 0;
  while (N < 16) and NextSpan(ALine, P, LTok[N]) do
  begin
    if (LTime < 0) and (LTok[N].Kind = '[') then
      LTime := N;
    Inc(N);
  end;
  { host ident user [time] "request" status bytes }
  if (LTime < 3) or (N < LTime + 4) then
    Exit;
  if not ParseIp(Raw(LTime - 3), E.Ip) then
    Exit;
  E.IpText := IpToStr(E.Ip);
  if LTime >= 4 then
    E.VHost := Raw(LTime - 4);
  E.TimeText := Text(LTime);
  E.Epoch := ParseApacheTime(E.TimeText);
  if LTok[LTime + 1].Kind <> '"' then
    Exit;
  E.Request := Text(LTime + 1);
  E.Status := StrToIntDef(Raw(LTime + 2), 0);
  E.Bytes := StrToInt64Def(Raw(LTime + 3), 0);
  if N > LTime + 4 then
    E.Referer := Text(LTime + 4);
  if N > LTime + 5 then
    E.Agent := Text(LTime + 5);
  SplitRequest(E);
  Result := True;
end;

procedure SplitRequest(var E: TAccessEntry);
var
  LReq: string;
  I, LSp: Integer;
begin
  { METHOD target PROTOCOL; a malformed request keeps it all in Target }
  LReq := E.Request;
  LSp := Pos(' ', LReq);
  if LSp > 0 then
  begin
    E.Method := Copy(LReq, 1, LSp - 1);
    LReq := Copy(LReq, LSp + 1, MaxInt);
    I := Length(LReq);
    while (I > 0) and (LReq[I] <> ' ') do
      Dec(I);
    if (I > 0) and (Copy(LReq, I + 1, 5) = 'HTTP/') then
    begin
      E.Protocol := Copy(LReq, I + 1, MaxInt);
      LReq := Copy(LReq, 1, I - 1);
    end;
    E.Target := LReq;
  end
  else
    E.Target := LReq;
  E.Decoded := UrlDecode(UrlDecode(ApacheUnescape(E.Target)));
end;

function CompactSummary(const E: TAccessEntry; const AClientAgent: string; AMaxLen: Integer): string;
begin
  { [10/Oct/2000:13:55:36 -0700] -> 13:55:36 }
  { concatenation, not Format: this runs for every line }
  Result := Copy(E.TimeText, 14, 8) + ' ' + E.Request + ' ' + IntToStr(E.Status) + ' ' + IntToStr(E.Bytes);
  if (E.Referer <> '-') and (E.Referer <> '') then
    Result := Result + ' ref="' + E.Referer + '"';
  if E.Agent <> AClientAgent then
    Result := Result + ' ua="' + E.Agent + '"';
  if Length(Result) > AMaxLen then
    Result := Copy(Result, 1, AMaxLen) + '...';
end;

function EntrySummary(const E: TAccessEntry; AMaxLen: Integer): string;
begin
  Result := Copy(E.TimeText, 2, 20) + ' "' + E.Request + '" ' + IntToStr(E.Status) + ' ' + IntToStr(E.Bytes) +
    ' ua="' + E.Agent + '"';
  if (E.Referer <> '-') and (E.Referer <> '') then
    Result := Result + ' ref="' + E.Referer + '"';
  if Length(Result) > AMaxLen then
    Result := Copy(Result, 1, AMaxLen) + '...';
end;

end.
