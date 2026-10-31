unit Ban.Tail;

(* tail -F for a set of log files. Patterns may hold wildcards in the file
   name (/var/log/apache2/*access.log); they are expanded again every few
   seconds, so a vhost log that appears later is picked up from its start.
   Rotation is handled both ways logrotate does it:
     - rename + create: the path now names another file (inode on Unix);
       the old file is drained to its end first, then the new one is read
       from the start;
     - copytruncate: the file got shorter than our position; start over.
   IIS (W3C) logs name their columns in "#Fields:" header lines; each file
   keeps its latest header and hands it out with every line it returns (the
   line's Objects[] entry), so files with different columns can be followed
   together. Opening at the end, the last header before it is looked up. *)

{$mode objfpc}{$H+}

interface

uses
  SysUtils, Classes, StrUtils, Contnrs, Ban.LogFormats {$IFDEF UNIX}, BaseUnix{$ENDIF};

type
  TTailFile = class
  public
    Path: string;
    Handle: THandle;
    Position: Int64;
    Ino: QWord;
    Partial: string;
    Seen: Boolean;      { still matched by a pattern on the last expansion }
    Layout: TW3CLayout; { the latest "#Fields:" header, nil if none }
    Layouts: TFPObjectList; { owns every layout handed out since the last Poll }
    constructor Create(const APath: string);
    destructor Destroy; override;
    function Open(AFromEnd: Boolean): Boolean;
    procedure Close;
    { appends whole lines to ALines; False when nothing new }
    function ReadNew(ALines: TStrings; AMaxBytes: Integer): Boolean;
    procedure CheckRotation;
    procedure SetLayout(const AFieldsLine: string);
    { forgets layouts that only lines already handed out (and processed) used }
    procedure Prune;
    (* the last "#Fields:" line before AEnd, '' if none. IIS writes one at the
       top of each file, so on a big file this reads it all, backwards, once
       at startup: about a second per GB from the page cache *)
    function LastFieldsLine(AEnd: Int64): string;
  end;

  TLogTailer = class
  private
    FPatterns: TStringList;
    FFiles: TStringList;      { path -> TTailFile }
    FRetired: TStringList;    { path=position of files let go for being idle }
    FFromStart: Boolean;
    FLastScan: QWord;
    FStarted: Boolean;
    procedure Rescan;
  public
    MaxLineLen: Integer;
    constructor Create(APatterns: TStrings; AFromStart: Boolean);
    destructor Destroy; override;
    { new lines from every file; False when there were none }
    function Poll(ALines: TStrings): Boolean;
    function FileCount: Integer;
    function FileNames: string;
  end;

implementation

const
  CChunk = 65536;
  CRescanMs = 5000;
  CMaxLine = 16384;

{$IFDEF UNIX}
function FileIno(const APath: string; out AIno: QWord; out ASize: Int64): Boolean;
var
  LSt: Stat;
begin
  Result := FpStat(APath, LSt) = 0;
  if Result then
  begin
    AIno := LSt.st_ino;
    ASize := LSt.st_size;
  end;
end;

function HandleIno(AHandle: THandle): QWord;
var
  LSt: Stat;
begin
  if FpFStat(AHandle, LSt) = 0 then
    Result := LSt.st_ino
  else
    Result := 0;
end;
{$ELSE}
function FileIno(const APath: string; out AIno: QWord; out ASize: Int64): Boolean;
var
  LRec: TSearchRec;
begin
  AIno := 0;
  Result := FindFirst(APath, faAnyFile, LRec) = 0;
  if Result then
    ASize := LRec.Size;
  FindClose(LRec);
end;

function HandleIno(AHandle: THandle): QWord;
begin
  Result := 0;
end;
{$ENDIF}

{ TTailFile }

constructor TTailFile.Create(const APath: string);
begin
  inherited Create;
  Path := APath;
  Handle := feInvalidHandle;
  Layouts := TFPObjectList.Create(True);
end;

destructor TTailFile.Destroy;
begin
  Close;
  Layouts.Free;
  inherited Destroy;
end;

procedure TTailFile.SetLayout(const AFieldsLine: string);
begin
  Layout := TW3CLayout.Create(AFieldsLine);
  Layouts.Add(Layout);
end;

procedure TTailFile.Prune;
begin
  while (Layouts.Count > 0) and (Layouts[0] <> Layout) do
    Layouts.Delete(0);
end;

function TTailFile.LastFieldsLine(AEnd: Int64): string;
const
  COverlap = 16;
  CScanChunk = 1024 * 1024;
var
  LPos, LStart, LFound: Int64;
  LBuf: string;
  LGot, I, P: Integer;
begin
  Result := '';
  LPos := AEnd;
  LFound := -1;
  while (LPos > 0) and (LFound < 0) do
  begin
    if LPos > CScanChunk then LStart := LPos - CScanChunk else LStart := 0;
    SetLength(LBuf, LPos - LStart + COverlap);
    FileSeek(Handle, LStart, fsFromBeginning);
    LGot := FileRead(Handle, LBuf[1], Length(LBuf));
    if LGot <= 0 then
      Break;
    SetLength(LBuf, LGot);
    { the last "#Fields:" that starts a line; one at the chunk's very start is
      judged with the chunk before it, which overlaps it }
    P := 0;
    repeat
      P := PosEx('#Fields:', LBuf, P + 1);
      if P = 0 then
        Break;
      if ((P = 1) and (LStart = 0)) or ((P > 1) and (LBuf[P - 1] = #10)) then
        if LStart + P - 1 < AEnd then
          LFound := LStart + P - 1;
    until False;
    LPos := LStart;
  end;
  if LFound < 0 then
    Exit;
  SetLength(LBuf, 8192);
  FileSeek(Handle, LFound, fsFromBeginning);
  LGot := FileRead(Handle, LBuf[1], Length(LBuf));
  if LGot <= 0 then
    Exit;
  SetLength(LBuf, LGot);
  I := Pos(#10, LBuf);
  if I > 0 then
    SetLength(LBuf, I - 1);
  Result := TrimRight(LBuf);
end;

function TTailFile.Open(AFromEnd: Boolean): Boolean;
var
  LFields: string;
begin
  Close;
  Handle := FileOpen(Path, fmOpenRead or fmShareDenyNone);
  if Handle = feInvalidHandle then
    Exit(False);
  Ino := HandleIno(Handle);
  Layout := nil;
  if AFromEnd then
  begin
    Position := FileSeek(Handle, Int64(0), fsFromEnd);
    LFields := LastFieldsLine(Position);
    if LFields <> '' then
      SetLayout(LFields);
  end
  else
    Position := 0;
  Partial := '';
  Result := True;
end;

procedure TTailFile.Close;
begin
  if Handle <> feInvalidHandle then
    FileClose(Handle);
  Handle := feInvalidHandle;
end;

function TTailFile.ReadNew(ALines: TStrings; AMaxBytes: Integer): Boolean;
var
  LBuf: array[0..CChunk - 1] of Char;
  LGot, LTotal, I, LStart: Integer;
  LLine: string;
begin
  Result := False;
  if Handle = feInvalidHandle then
    Exit;
  LTotal := 0;
  FileSeek(Handle, Position, fsFromBeginning);
  repeat
    LGot := FileRead(Handle, LBuf[0], CChunk);
    if LGot <= 0 then
      Break;
    Inc(Position, LGot);
    Inc(LTotal, LGot);
    LStart := 0;
    for I := 0 to LGot - 1 do
      if LBuf[I] = #10 then
      begin
        SetString(LLine, PChar(@LBuf[LStart]), I - LStart);
        LLine := Partial + LLine;
        Partial := '';
        if (LLine <> '') and (LLine[Length(LLine)] = #13) then
          SetLength(LLine, Length(LLine) - 1);
        if Length(LLine) > CMaxLine then
          SetLength(LLine, CMaxLine);
        if IsW3CFieldsLine(LLine) then
          SetLayout(LLine)
        else if LLine <> '' then
          ALines.AddObject(LLine, Layout);
        LStart := I + 1;
        Result := True;
      end;
    if LStart < LGot then
    begin
      SetString(LLine, PChar(@LBuf[LStart]), LGot - LStart);
      if Length(Partial) < CMaxLine then
        Partial := Partial + LLine;
    end;
  until LTotal >= AMaxBytes;
end;

procedure TTailFile.CheckRotation;
var
  LIno: QWord;
  LSize: Int64;
begin
  if not FileIno(Path, LIno, LSize) then
    Exit;   { between rename and create: keep reading the old file }
  if Handle = feInvalidHandle then
  begin
    Open(False);
    Exit;
  end;
  { renamed away (another inode): TLogTailer.Poll drains it and reopens }
  if (LIno <> 0) and (LIno <> Ino) then
    Exit;
  if LSize < Position then
  begin
    Position := 0;
    Partial := '';
  end;
end;

{ TLogTailer }

constructor TLogTailer.Create(APatterns: TStrings; AFromStart: Boolean);
begin
  inherited Create;
  FPatterns := TStringList.Create;
  FPatterns.Assign(APatterns);
  FFiles := TStringList.Create;
  FFiles.Sorted := True;
  FFiles.OwnsObjects := True;
  FRetired := TStringList.Create;
  FFromStart := AFromStart;
  MaxLineLen := CMaxLine;
  Rescan;
  FStarted := True;
end;

destructor TLogTailer.Destroy;
begin
  FFiles.Free;
  FRetired.Free;
  FPatterns.Free;
  inherited Destroy;
end;

procedure TLogTailer.Rescan;
var
  LPattern, LDir, LPath: string;
  LRec: TSearchRec;
  LFile: TTailFile;
  I, J: Integer;
  LPos: Int64;
begin
  for I := 0 to FFiles.Count - 1 do
    TTailFile(FFiles.Objects[I]).Seen := False;
  for LPattern in FPatterns do
  begin
    if (Pos('*', LPattern) = 0) and (Pos('?', LPattern) = 0) then
    begin
      { a plain path is followed even before it exists }
      I := FFiles.IndexOf(LPattern);
      if I < 0 then
      begin
        LFile := TTailFile.Create(LPattern);
        FFiles.AddObject(LPattern, LFile);
        LFile.Open(not FFromStart and not FStarted);
      end
      else
        LFile := TTailFile(FFiles.Objects[I]);
      LFile.Seen := True;
      Continue;
    end;
    LDir := ExtractFilePath(LPattern);
    if FindFirst(LPattern, faAnyFile and not faDirectory, LRec) = 0 then
    try
      repeat
        LPath := LDir + LRec.Name;
        I := FFiles.IndexOf(LPath);
        (* a match nobody has written to for a day is finished: IIS starts a
           new u_exYYMMDD.log every day and keeps the old ones forever, so
           u_ex*.log would otherwise hold a handle on years of logs, and a
           daemon running for months would gain one file a day *)
        if (LRec.Time <> -1) and (Now - FileDateToDateTime(LRec.Time) > 1) and
           ((I < 0) or (TTailFile(FFiles.Objects[I]).Position >= LRec.Size)) then
          Continue;   { not Seen: one we were following is let go below }
        if I < 0 then
        begin
          LFile := TTailFile.Create(LPath);
          FFiles.AddObject(LPath, LFile);
          { files there at startup start at their end; later ones at 0; one let go
            for being idle carries on where it was (or at 0 if it was truncated) }
          LFile.Open(not FFromStart and not FStarted);
          J := FRetired.IndexOfName(LPath);
          if J >= 0 then
          begin
            LPos := StrToInt64Def(FRetired.ValueFromIndex[J], 0);
            if LPos <= LRec.Size then
              LFile.Position := LPos;
            FRetired.Delete(J);
          end;
        end
        else
          LFile := TTailFile(FFiles.Objects[I]);
        LFile.Seen := True;
      until FindNext(LRec) <> 0;
    finally
      FindClose(LRec);
    end;
  end;
  for I := FFiles.Count - 1 downto 0 do
    if not TTailFile(FFiles.Objects[I]).Seen then
    begin
      if FRetired.Count < 100000 then
        FRetired.Values[FFiles[I]] := IntToStr(TTailFile(FFiles.Objects[I]).Position);
      FFiles.Delete(I);
    end;
  FLastScan := GetTickCount64;
end;

function TLogTailer.Poll(ALines: TStrings): Boolean;
var
  I: Integer;
  LFile: TTailFile;
  LIno: QWord;
  LSize: Int64;
begin
  if GetTickCount64 - FLastScan >= CRescanMs then
    Rescan;
  Result := False;
  for I := 0 to FFiles.Count - 1 do
  begin
    LFile := TTailFile(FFiles.Objects[I]);
    LFile.Prune;
    if LFile.ReadNew(ALines, 4 * CChunk) then
      Result := True;
    LFile.CheckRotation;
    if (LFile.Handle <> feInvalidHandle) and FileIno(LFile.Path, LIno, LSize) and
       (LIno <> 0) and (LIno <> LFile.Ino) then
    begin
      { rotated by rename: finish the old file, then follow the new one }
      while LFile.ReadNew(ALines, MaxInt) do
        Result := True;
      LFile.Open(False);
      if LFile.ReadNew(ALines, 4 * CChunk) then
        Result := True;
    end;
  end;
end;

function TLogTailer.FileCount: Integer;
begin
  Result := FFiles.Count;
end;

function TLogTailer.FileNames: string;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to FFiles.Count - 1 do
  begin
    if Result <> '' then
      Result := Result + ', ';
    Result := Result + FFiles[I];
  end;
  if Result = '' then
    Result := '(none yet)';
end;

end.
