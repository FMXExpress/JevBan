unit Ban.BadPaths;

(* Known-bad paths: what vulnerability scanners probe for (data/badpaths.txt,
   from SecLists' quickhits). Two lookups on the request's path:

   - exact: a sorted list, one binary search;
   - near:  within an edit distance that grows with the length (0 below 8
            characters, 1 up to 15, 2 from 16), through a BK-tree, so a
            probe for /wp-config.php.bak1 or /phpmyadmin4 is caught without a
            regex for every variant. Short paths get no fuzz: /.env and /.dev
            are one edit apart.

   Encodings are not the edit distance's job: the path is compared after
   Ban.Apache decoded \xhh and %hh (twice), lowercased, without the query
   string, with // and /./ collapsed and no trailing slash. *)

{$mode objfpc}{$H+}

interface

uses
  SysUtils, Classes, Math;

type
  TBkChild = record
    Dist: Integer;
    Node: Integer;
  end;

  TBkNode = record
    Text: string;
    Kids: array of TBkChild;
  end;

  TBadPaths = class
  private
    FExact: TStringList;
    FTree: array of TBkNode;
    FCount: Integer;
    procedure TreeAdd(const S: string);
  public
    constructor Create;
    destructor Destroy; override;
    procedure LoadFile(const AFile: string);
    procedure Add(const APath: string);
    function IsExact(const ANormPath: string): Boolean;
    { the closest known-bad path within the length's edit allowance; '' if none }
    function Near(const ANormPath: string; out ADist: Integer): string;
    function Count: Integer;
  end;

{ decoded request target -> the form the list is kept in }
function NormalizePath(const ADecoded: string): string;
{ edits allowed for a path of this length }
function FuzzAllowance(ALen: Integer): Integer;
{ Levenshtein distance, giving up (AMax + 1) once it must exceed AMax }
function BoundedLevenshtein(const A, B: string; AMax: Integer): Integer;
(* a normalized path that asks for code, configuration, data or a backup by name
   (archives are left out: a dead download link is common, and backup-named
   archives are the backup-file signature's)
   (/old/db.sql, /Admin.asp, /config.json, /.npmrc): what a scanner asks for and a
   visitor's broken link almost never is. On the LogarX shop every one of the 130
   benign 4xx had no extension; the attacks' 4xx had 1,100 of these *)
function IsFileProbe(const APath: string): Boolean;

implementation

const
  CProbeExts: array[0..64] of string = (
    'php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'inc', 'asp', 'aspx', 'ashx', 'asmx',
    'axd', 'cfm', 'cgi', 'pl', 'py', 'rb', 'jsp', 'jspx', 'do', 'action', 'sh', 'bash',
    'exe', 'dll', 'bat', 'cmd', 'ps1', 'vb', 'cs', 'java', 'config', 'conf', 'cfg', 'ini',
    'env', 'yml', 'yaml', 'toml', 'properties', 'json', 'txt', 'sql', 'db', 'sqlite',
    'sqlite3', 'mdb', 'bak', 'old', 'orig', 'save', 'swp', 'tmp', 'temp', 'backup', 'bk',
    'log', 'war', 'jar', 'key', 'pem',
    'p12', 'pfx', 'lock', 'dist');
  (* names a browser, crawler or monitor asks for whether or not the site has them *)
  CWellKnown: array[0..8] of string = (
    'robots.txt', 'ads.txt', 'app-ads.txt', 'humans.txt', 'security.txt', 'llms.txt',
    'manifest.json', 'sellers.json', 'index.php');

function IsFileProbe(const APath: string): Boolean;
var
  P, I: Integer;
  LName, LExt: string;
begin
  Result := False;
  if Pos('/.well-known/', APath + '/') = 1 then
    Exit;
  P := Length(APath);
  while (P > 0) and (APath[P] <> '/') do
    Dec(P);
  LName := Copy(APath, P + 1, MaxInt);
  if LName = '' then
    Exit;
  for I := Low(CWellKnown) to High(CWellKnown) do
    if LName = CWellKnown[I] then
      Exit;
  { a dotfile (/.env, /.git/config's directory is caught by the bad-path list) }
  if (LName[1] = '.') and (Length(LName) > 1) and (Pos('.', Copy(LName, 2, MaxInt)) = 0) then
    Exit(True);
  P := Length(LName);
  while (P > 1) and (LName[P] <> '.') do
    Dec(P);
  if P <= 1 then
    Exit;
  LExt := Copy(LName, P + 1, MaxInt);
  for I := Low(CProbeExts) to High(CProbeExts) do
    if LExt = CProbeExts[I] then
      Exit(True);
end;

function NormalizePath(const ADecoded: string): string;
var
  P: Integer;
begin
  Result := ADecoded;
  P := Pos('?', Result);
  if P > 0 then
    SetLength(Result, P - 1);
  P := Pos('#', Result);
  if P > 0 then
    SetLength(Result, P - 1);
  Result := LowerCase(Result);
  Result := StringReplace(Result, '\', '/', [rfReplaceAll]);
  while Pos('//', Result) > 0 do
    Result := StringReplace(Result, '//', '/', [rfReplaceAll]);
  while Pos('/./', Result) > 0 do
    Result := StringReplace(Result, '/./', '/', [rfReplaceAll]);
  if (Result = '') or (Result[1] <> '/') then
    Result := '/' + Result;
  while (Length(Result) > 1) and (Result[Length(Result)] = '/') do
    SetLength(Result, Length(Result) - 1);
end;

function FuzzAllowance(ALen: Integer): Integer;
begin
  if ALen < 8 then
    Result := 0
  else if ALen < 16 then
    Result := 1
  else
    Result := 2;
end;

function BoundedLevenshtein(const A, B: string; AMax: Integer): Integer;
var
  LPrev, LCur: array of Integer;
  I, J, LCost, LRowMin: Integer;
begin
  if Abs(Length(A) - Length(B)) > AMax then
    Exit(AMax + 1);
  SetLength(LPrev, Length(B) + 1);
  SetLength(LCur, Length(B) + 1);
  for J := 0 to Length(B) do
    LPrev[J] := J;
  for I := 1 to Length(A) do
  begin
    LCur[0] := I;
    LRowMin := LCur[0];
    for J := 1 to Length(B) do
    begin
      LCost := Ord(A[I] <> B[J]);
      LCur[J] := Min(Min(LPrev[J] + 1, LCur[J - 1] + 1), LPrev[J - 1] + LCost);
      if LCur[J] < LRowMin then
        LRowMin := LCur[J];
    end;
    if LRowMin > AMax then
      Exit(AMax + 1);
    for J := 0 to Length(B) do
      LPrev[J] := LCur[J];
  end;
  Result := Min(LPrev[Length(B)], AMax + 1);
end;

{ TBadPaths }

constructor TBadPaths.Create;
begin
  inherited Create;
  FExact := TStringList.Create;
  FExact.Sorted := True;
  FExact.Duplicates := dupIgnore;
  FExact.CaseSensitive := True;
end;

destructor TBadPaths.Destroy;
begin
  FExact.Free;
  inherited Destroy;
end;

procedure TBadPaths.TreeAdd(const S: string);
var
  LNode, D, I: Integer;
  LFound: Boolean;
begin
  if Length(FTree) = 0 then
  begin
    SetLength(FTree, 1);
    FTree[0].Text := S;
    Exit;
  end;
  LNode := 0;
  repeat
    { an unbounded distance: the tree needs the exact value }
    D := BoundedLevenshtein(S, FTree[LNode].Text, MaxInt div 2);
    if D = 0 then
      Exit;
    LFound := False;
    for I := 0 to High(FTree[LNode].Kids) do
      if FTree[LNode].Kids[I].Dist = D then
      begin
        LNode := FTree[LNode].Kids[I].Node;
        LFound := True;
        Break;
      end;
    if not LFound then
    begin
      SetLength(FTree, Length(FTree) + 1);
      FTree[High(FTree)].Text := S;
      I := Length(FTree[LNode].Kids);
      SetLength(FTree[LNode].Kids, I + 1);
      FTree[LNode].Kids[I].Dist := D;
      FTree[LNode].Kids[I].Node := High(FTree);
      Exit;
    end;
  until False;
end;

procedure TBadPaths.Add(const APath: string);
var
  LPath: string;
begin
  LPath := NormalizePath(Trim(APath));
  if Length(LPath) < 3 then
    Exit;
  if FExact.IndexOf(LPath) >= 0 then
    Exit;
  FExact.Add(LPath);
  Inc(FCount);
  { a near match is at most 2 edits from a query of 8 or more characters }
  if Length(LPath) >= 6 then
    TreeAdd(LPath);
end;

procedure TBadPaths.LoadFile(const AFile: string);
var
  LLines: TStringList;
  LLine: string;
begin
  LLines := TStringList.Create;
  try
    LLines.LoadFromFile(AFile);
    for LLine in LLines do
      if (Trim(LLine) <> '') and (Trim(LLine)[1] <> '#') then
        Add(LLine);
  finally
    LLines.Free;
  end;
end;

function TBadPaths.IsExact(const ANormPath: string): Boolean;
var
  I: Integer;
begin
  Result := FExact.Find(ANormPath, I);
end;

function TBadPaths.Near(const ANormPath: string; out ADist: Integer): string;
var
  LStack: array of Integer;
  LTop, LNode, D, I, LMax: Integer;
begin
  Result := '';
  ADist := MaxInt;
  LMax := FuzzAllowance(Length(ANormPath));
  if (LMax = 0) or (Length(FTree) = 0) then
    Exit;
  SetLength(LStack, Length(FTree));
  LTop := 0;
  LStack[0] := 0;
  while LTop >= 0 do
  begin
    LNode := LStack[LTop];
    Dec(LTop);
    { pruning by the triangle inequality needs the exact distance }
    D := BoundedLevenshtein(ANormPath, FTree[LNode].Text, MaxInt div 2);
    if (D <= LMax) and (D < ADist) then
    begin
      ADist := D;
      Result := FTree[LNode].Text;
    end;
    for I := 0 to High(FTree[LNode].Kids) do
      if Abs(FTree[LNode].Kids[I].Dist - D) <= LMax then
      begin
        Inc(LTop);
        LStack[LTop] := FTree[LNode].Kids[I].Node;
      end;
  end;
  if Result = '' then
    ADist := 0;
end;

function TBadPaths.Count: Integer;
begin
  Result := FCount;
end;

end.
