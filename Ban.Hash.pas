unit Ban.Hash;

(* A string-keyed hash map for the per-line hot paths: clients by address,
   and the caches of signature and near-miss results by field value. Open
   addressing with linear probing and backward-shift deletion (no tombstones,
   so a long-running daemon that adds and drops millions of clients keeps
   short probe chains); FNV-1a hashing. Keys are any length, values are
   objects, freed by the map when OwnsObjects is set. *)

{$mode objfpc}{$H+}

interface

uses
  SysUtils;

type
  TStrMap = class
  private
    FKeys: array of string;
    FValues: array of TObject;
    FHashes: array of QWord;   { 0 = empty slot }
    FCount, FMask: Integer;
    FOwns: Boolean;
    function Slot(const AKey: string; AHash: QWord): Integer;
    procedure Grow;
    procedure FreeValue(AIdx: Integer);
  public
    constructor Create(AOwnsObjects: Boolean; ACapacity: Integer = 64);
    destructor Destroy; override;
    function Get(const AKey: string): TObject;
    { adds or replaces (a replaced value is freed when the map owns it) }
    procedure Put(const AKey: string; AValue: TObject);
    function Delete(const AKey: string): Boolean;
    procedure Clear;
    property Count: Integer read FCount;
    { iteration over the slots: for I := 0 to Capacity - 1 do if Used(I) then ... Keys[I], Values[I] }
    function Capacity: Integer;
    function Used(AIdx: Integer): Boolean; inline;
    function KeyAt(AIdx: Integer): string; inline;
    function ValueAt(AIdx: Integer): TObject; inline;
  end;

function HashStr(const S: string): QWord;

implementation

function HashStr(const S: string): QWord;
var
  I: Integer;
begin
  Result := QWord($CBF29CE484222325);
  for I := 1 to Length(S) do
  begin
    Result := Result xor Ord(S[I]);
    {$PUSH}{$Q-}{$R-}
    Result := Result * QWord($100000001B3);
    {$POP}
  end;
  if Result = 0 then
    Result := 1;
end;

constructor TStrMap.Create(AOwnsObjects: Boolean; ACapacity: Integer);
var
  N: Integer;
begin
  inherited Create;
  FOwns := AOwnsObjects;
  N := 16;
  while N < ACapacity * 2 do
    N := N * 2;
  SetLength(FKeys, N);
  SetLength(FValues, N);
  SetLength(FHashes, N);
  FMask := N - 1;
end;

destructor TStrMap.Destroy;
begin
  Clear;
  inherited Destroy;
end;

function TStrMap.Capacity: Integer;
begin
  Result := FMask + 1;
end;

function TStrMap.Used(AIdx: Integer): Boolean;
begin
  Result := FHashes[AIdx] <> 0;
end;

function TStrMap.KeyAt(AIdx: Integer): string;
begin
  Result := FKeys[AIdx];
end;

function TStrMap.ValueAt(AIdx: Integer): TObject;
begin
  Result := FValues[AIdx];
end;

procedure TStrMap.FreeValue(AIdx: Integer);
begin
  if FOwns then
    FValues[AIdx].Free;
  FValues[AIdx] := nil;
end;

{ the slot holding AKey, or the empty slot where it would go }
function TStrMap.Slot(const AKey: string; AHash: QWord): Integer;
begin
  Result := Integer(AHash and QWord(FMask));
  while (FHashes[Result] <> 0) and ((FHashes[Result] <> AHash) or (FKeys[Result] <> AKey)) do
    Result := (Result + 1) and FMask;
end;

procedure TStrMap.Grow;
var
  LKeys: array of string;
  LValues: array of TObject;
  LHashes: array of QWord;
  I, J, N: Integer;
begin
  LKeys := FKeys;
  LValues := FValues;
  LHashes := FHashes;
  N := (FMask + 1) * 2;
  FKeys := nil;
  FValues := nil;
  FHashes := nil;
  SetLength(FKeys, N);
  SetLength(FValues, N);
  SetLength(FHashes, N);
  FMask := N - 1;
  for I := 0 to High(LHashes) do
    if LHashes[I] <> 0 then
    begin
      J := Integer(LHashes[I] and QWord(FMask));
      while FHashes[J] <> 0 do
        J := (J + 1) and FMask;
      FHashes[J] := LHashes[I];
      FKeys[J] := LKeys[I];
      FValues[J] := LValues[I];
    end;
end;

function TStrMap.Get(const AKey: string): TObject;
var
  I: Integer;
begin
  I := Slot(AKey, HashStr(AKey));
  if FHashes[I] = 0 then
    Result := nil
  else
    Result := FValues[I];
end;

procedure TStrMap.Put(const AKey: string; AValue: TObject);
var
  H: QWord;
  I: Integer;
begin
  { at most half full: probe chains stay short }
  if (FCount + 1) * 2 > FMask + 1 then
    Grow;
  H := HashStr(AKey);
  I := Slot(AKey, H);
  if FHashes[I] <> 0 then
  begin
    if FValues[I] <> AValue then
      FreeValue(I);
    FValues[I] := AValue;
    Exit;
  end;
  FHashes[I] := H;
  FKeys[I] := AKey;
  FValues[I] := AValue;
  Inc(FCount);
end;

function TStrMap.Delete(const AKey: string): Boolean;
var
  I, J, K: Integer;
begin
  I := Slot(AKey, HashStr(AKey));
  if FHashes[I] = 0 then
    Exit(False);
  FreeValue(I);
  FKeys[I] := '';
  FHashes[I] := 0;
  Dec(FCount);
  (* backward shift: move later entries of the chain into the hole when their
     home slot does not lie cyclically in (hole, their slot] *)
  J := I;
  repeat
    J := (J + 1) and FMask;
    if FHashes[J] = 0 then
      Break;
    K := Integer(FHashes[J] and QWord(FMask));
    if ((J > I) and ((K <= I) or (K > J))) or ((J < I) and (K <= I) and (K > J)) then
    begin
      FHashes[I] := FHashes[J];
      FKeys[I] := FKeys[J];
      FValues[I] := FValues[J];
      FHashes[J] := 0;
      FKeys[J] := '';
      FValues[J] := nil;
      I := J;
    end;
  until False;
  Result := True;
end;

procedure TStrMap.Clear;
var
  I: Integer;
begin
  for I := 0 to FMask do
    if FHashes[I] <> 0 then
    begin
      FreeValue(I);
      FKeys[I] := '';
      FHashes[I] := 0;
    end;
  FCount := 0;
end;

end.
