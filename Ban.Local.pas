unit Ban.Local;

(* OpenJev in-process: the decision model runs inside jevban on llama.cpp,
   so nothing else has to be installed or served. On first use the GGUF is
   downloaded from Hugging Face (openjev/OpenJev-Flash-9B-GGUF by default).

   The readout is OpenJev's helper (helper/shim.py), done by hand:
     prompt  = <|im_start|>user\n
               State:\n<state as json.dumps(ensure_ascii=False)>\n\n
               Question: <instructions>\nOptions:\n[A] yes: ..\n[B] no: ..\n\n
               Answer with the letter of the best option only.<|im_end|>\n
               <|im_start|>assistant\n<think>\n\n</think>\n\n
     scores  = the logits of the option letters at the first output position
     p       = softmax(logit / T) over the options
     noul    = sigmoid(logit(p_yes) / noul_t + noul_bias)
   with the T / noul_t / noul_bias the model card gives for the family (the
   log-sum-exp a logprob would subtract is the same for every letter, so
   raw logits give the same p). Each client is its own prompt with only its
   own requests in the state. *)

{$mode objfpc}{$H+}

interface

uses
  SysUtils, Classes, Math, DateUtils, Ban.Jev, Ban.Llama;

type
  TDoubleArray = array of Double;

type
  TLocalModelInfo = record
    Key: string;
    Repo: string;
    FileName: string;
    Size: Int64;
    T, NoulT, NoulBias: Double;
  end;

  TLogProc = procedure(const AMsg: string) of object;

  TLocalJudge = class(TDecider)
  private
    FModel: PLlamaModel;
    FCtx: PLlamaContext;
    FVocab: PLlamaVocab;
    FNVocab: Integer;
    FNCtx, FNBatch: Integer;
    FLetters: array[0..51] of TLlamaToken;
    FDesc: string;
    function Tokenize(const AText: string; ASpecial: Boolean): TLlamaTokens;
    function Readout(const APrompt: string; ANOptions: Integer): TDoubleArray;
    function Prompt(const AState, AInstructions: string; const AOptions: array of string): string;
    function StateJson(AItem: TJevItem): string;
  public
    Site: string;
    Question: string;
    AskIntent: Boolean;
    T, NoulT, NoulBias: Double;
    constructor Create(const AModelPath, ALibDir: string; AThreads, AGpuLayers, ANCtx: Integer);
    destructor Destroy; override;
    function Decide(AItems: TList; out AError: string; out ALatencyMs: Int64): Boolean; override;
    function Describe: string; override;
  end;

const
  CLocalModels: array[0..7] of TLocalModelInfo = (
    (Key: 'flash-9b'; Repo: 'openjev/OpenJev-Flash-9B-GGUF'; FileName: 'OpenJev-Flash-9B-Q4_K_M.gguf';
      Size: 5629109120; T: 1.07; NoulT: 1.074766; NoulBias: 0),
    (Key: 'flash-9b-q5'; Repo: 'openjev/OpenJev-Flash-9B-GGUF'; FileName: 'OpenJev-Flash-9B-Q5_K_M.gguf';
      Size: 6467969920; T: 1.07; NoulT: 1.074766; NoulBias: 0),
    (Key: 'flash-9b-q6'; Repo: 'openjev/OpenJev-Flash-9B-GGUF'; FileName: 'OpenJev-Flash-9B-Q6_K.gguf';
      Size: 7359259520; T: 1.07; NoulT: 1.074766; NoulBias: 0),
    (Key: 'flash-9b-q8'; Repo: 'openjev/OpenJev-Flash-9B-GGUF'; FileName: 'OpenJev-Flash-9B-Q8_0.gguf';
      Size: 9527501696; T: 1.07; NoulT: 1.074766; NoulBias: 0),
    (Key: '27b'; Repo: 'openjev/openjev-GGUF'; FileName: 'OpenJev-Q4_K_M.gguf';
      Size: 16547400000; T: 0.85; NoulT: 1.829074; NoulBias: 0),
    (Key: '27b-q5'; Repo: 'openjev/openjev-GGUF'; FileName: 'OpenJev-Q5_K_M.gguf';
      Size: 19231099200; T: 0.85; NoulT: 1.829074; NoulBias: 0),
    (Key: '27b-q6'; Repo: 'openjev/openjev-GGUF'; FileName: 'OpenJev-Q6_K.gguf';
      Size: 22082529600; T: 0.85; NoulT: 1.829074; NoulBias: 0),
    (Key: '27b-q8'; Repo: 'openjev/openjev-GGUF'; FileName: 'OpenJev-Q8_0.gguf';
      Size: 28595763520; T: 0.85; NoulT: 1.829074; NoulBias: 0));

{ the table entry for AKey; False for a path to a .gguf of your own }
function FindLocalModel(const AKey: string; out AInfo: TLocalModelInfo): Boolean;
{ AKey's GGUF in AModelDir, downloaded first if missing; or AKey itself when
  it is a path. Raises when it cannot be had. }
function EnsureLocalModel(const AKey, AModelDir: string; ALog: TLogProc): string;
function LocalModelKeys: string;
{ Python's json.dumps(s, ensure_ascii=False) for a string }
function PyJsonStr(const S: string): string;

implementation

uses
  Ban.Https;

function FindLocalModel(const AKey: string; out AInfo: TLocalModelInfo): Boolean;
var
  I: Integer;
begin
  for I := 0 to High(CLocalModels) do
    if SameText(CLocalModels[I].Key, AKey) then
    begin
      AInfo := CLocalModels[I];
      Exit(True);
    end;
  Result := False;
end;

function LocalModelKeys: string;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to High(CLocalModels) do
  begin
    if Result <> '' then
      Result := Result + ', ';
    Result := Result + CLocalModels[I].Key;
  end;
end;

function FileSize64(const APath: string): Int64;
var
  LRec: TSearchRec;
begin
  Result := -1;
  if FindFirst(APath, faAnyFile, LRec) = 0 then
    Result := LRec.Size;
  FindClose(LRec);
end;

function EnsureLocalModel(const AKey, AModelDir: string; ALog: TLogProc): string;
var
  LInfo: TLocalModelInfo;
  LSize: Int64;
begin
  if not FindLocalModel(AKey, LInfo) then
  begin
    if not FileExists(AKey) then
      raise Exception.CreateFmt('local_model "%s" is neither a file nor one of: %s', [AKey, LocalModelKeys]);
    Exit(AKey);
  end;
  Result := IncludeTrailingPathDelimiter(AModelDir) + LInfo.FileName;
  LSize := FileSize64(Result);
  if LSize = LInfo.Size then
    Exit;
  if LSize >= 0 then
    ALog(Format('%s is %d bytes, expected %d; downloading it again', [Result, LSize, LInfo.Size]));
  ALog(Format('downloading OpenJev %s (%.1f GB, once) from huggingface.co/%s into %s',
    [LInfo.Key, LInfo.Size / 1e9, LInfo.Repo, AModelDir]));
  ALog('OpenJev weights are CC BY-NC 4.0: free for non-commercial use; a commercial licence is ' +
    'available from support@loopai.com');
  HttpsGetToFile(Format('https://huggingface.co/%s/resolve/main/%s', [LInfo.Repo, LInfo.FileName]), Result);
  LSize := FileSize64(Result);
  if LSize <> LInfo.Size then
  begin
    DeleteFile(Result);
    raise Exception.CreateFmt('download of %s ended at %d bytes, expected %d', [LInfo.FileName, LSize, LInfo.Size]);
  end;
end;

function PyJsonStr(const S: string): string;
var
  C: Char;
begin
  Result := '"';
  for C in S do
    case C of
      '"': Result := Result + '\"';
      '\': Result := Result + '\\';
      #10: Result := Result + '\n';
      #13: Result := Result + '\r';
      #9: Result := Result + '\t';
      #8: Result := Result + '\b';
      #12: Result := Result + '\f';
      #0..#7, #11, #14..#31: Result := Result + '\u' + LowerCase(IntToHex(Ord(C), 4));
    else
      Result := Result + C;
    end;
  Result := Result + '"';
end;

function PyJsonList(AList: TStrings): string;
var
  I: Integer;
begin
  Result := '[';
  for I := 0 to AList.Count - 1 do
  begin
    if I > 0 then
      Result := Result + ', ';
    Result := Result + PyJsonStr(AList[I]);
  end;
  Result := Result + ']';
end;

{ FPC 3.2.2's TThread.ProcessorCount and GetCPUCount are 1 on Linux }
function CpuCount: Integer;
{$IFDEF LINUX}
var
  LInfo: TStringList;
  LLine: string;
begin
  Result := 0;
  LInfo := TStringList.Create;
  try
    try
      LInfo.LoadFromFile('/proc/cpuinfo');
    except
      on E: EStreamError do
        Exit(1);
    end;
    for LLine in LInfo do
      if Copy(LLine, 1, 9) = 'processor' then
        Inc(Result);
  finally
    LInfo.Free;
  end;
  Result := Max(1, Result);
end;
{$ELSE}
begin
  Result := Max(1, Integer(GetCPUCount));
end;
{$ENDIF}

procedure QuietLog(ALevel: Int32; AText: PAnsiChar; AUserData: Pointer); cdecl;
begin
  { GGML_LOG_LEVEL_ERROR = 4; the rest is load chatter }
  if (ALevel = 4) and (AText <> nil) then
    Write(StdErr, '[llama] ', AText);
end;

{ TLocalJudge }

constructor TLocalJudge.Create(const AModelPath, ALibDir: string; AThreads, AGpuLayers, ANCtx: Integer);
var
  MP: TLlamaModelParams;
  CP: TLlamaContextParams;
  LTok: TLlamaTokens;
  LBuf: array[0..255] of AnsiChar;
  I: Integer;
  LLetter: string;
begin
  inherited Create;
  Question := CDefaultQuestion;
  Site := CDefaultSite;
  LlamaLoad(ALibDir);
  if GetEnvironmentVariable('JEVBAN_LLAMA_DEBUG') <> '1' then
    llama_log_set(@QuietLog, nil);
  llama_backend_init;
  MP := llama_model_default_params();
  MP.n_gpu_layers := AGpuLayers;
  FModel := llama_model_load_from_file(PAnsiChar(AnsiString(AModelPath)), MP);
  if FModel = nil then
    raise Exception.CreateFmt('llama.cpp could not load %s (JEVBAN_LLAMA_DEBUG=1 shows why)', [AModelPath]);
  FVocab := llama_model_get_vocab(FModel);
  FNVocab := llama_vocab_n_tokens(FVocab);
  if AThreads <= 0 then
    AThreads := Max(1, CpuCount - 1);
  FNCtx := ANCtx;
  FNBatch := 512;
  CP := llama_context_default_params();
  CP.n_ctx := FNCtx;
  CP.n_batch := FNBatch;
  CP.n_ubatch := FNBatch;
  CP.n_threads := AThreads;
  CP.n_threads_batch := AThreads;
  CP.no_perf := True;
  FCtx := llama_init_from_model(FModel, CP);
  if FCtx = nil then
    raise Exception.Create('llama.cpp could not create a context');
  { the option letters as the helper encodes them: tokenizer.encode(L)[0] }
  for I := 0 to 51 do
  begin
    if I < 26 then
      LLetter := Chr(65 + I)
    else
      LLetter := Chr(97 + I - 26);
    LTok := Tokenize(LLetter, False);
    if Length(LTok) <> 1 then
      raise Exception.CreateFmt('the model''s vocabulary splits the letter %s', [LLetter]);
    FLetters[I] := LTok[0];
  end;
  FillChar(LBuf, SizeOf(LBuf), 0);
  llama_model_desc(FModel, @LBuf[0], SizeOf(LBuf) - 1);
  FDesc := Format('local %s (%s, %d threads)', [ExtractFileName(AModelPath), string(PAnsiChar(@LBuf[0])), AThreads]);
end;

destructor TLocalJudge.Destroy;
begin
  if FCtx <> nil then
    llama_free(FCtx);
  if FModel <> nil then
    llama_model_free(FModel);
  inherited Destroy;
end;

function TLocalJudge.Describe: string;
begin
  Result := FDesc;
end;

function TLocalJudge.Tokenize(const AText: string; ASpecial: Boolean): TLlamaTokens;
var
  N: Integer;
begin
  Result := nil;
  SetLength(Result, Length(AText) + 16);
  N := llama_tokenize(FVocab, PAnsiChar(AText), Length(AText), @Result[0], Length(Result), False, ASpecial);
  if N < 0 then
  begin
    SetLength(Result, -N);
    N := llama_tokenize(FVocab, PAnsiChar(AText), Length(AText), @Result[0], Length(Result), False, ASpecial);
  end;
  if N < 0 then
    raise Exception.Create('tokenize failed');
  SetLength(Result, N);
end;

function TLocalJudge.Prompt(const AState, AInstructions: string; const AOptions: array of string): string;
var
  I: Integer;
  LText, LLetter: string;
begin
  LText := 'State:' + #10 + AState + #10#10 + 'Question: ' + AInstructions + #10 + 'Options:';
  I := 0;
  while I < High(AOptions) do
  begin
    if I div 2 < 26 then
      LLetter := Chr(65 + I div 2)
    else
      LLetter := Chr(97 + I div 2 - 26);
    LText := LText + #10 + '[' + LLetter + '] ' + AOptions[I] + ': ' + AOptions[I + 1];
    Inc(I, 2);
  end;
  LText := LText + #10#10 + 'Answer with the letter of the best option only.';
  { the chat template, one user message, enable_thinking=false }
  Result := '<|im_start|>user' + #10 + Trim(LText) + '<|im_end|>' + #10 + '<|im_start|>assistant' + #10 +
    '<think>' + #10#10 + '</think>' + #10#10;
end;

function TLocalJudge.Readout(const APrompt: string; ANOptions: Integer): TDoubleArray;
var
  LTokens: TLlamaTokens;
  LAt, LN, I: Integer;
  LLogits: PSingle;
  LMax, LSum: Double;
begin
  Result := nil;
  LTokens := Tokenize(APrompt, True);
  if Length(LTokens) >= FNCtx then
    raise Exception.CreateFmt('prompt of %d tokens does not fit the %d-token context', [Length(LTokens), FNCtx]);
  llama_memory_clear(llama_get_memory(FCtx), True);
  LAt := 0;
  while LAt < Length(LTokens) do
  begin
    LN := Min(FNBatch, Length(LTokens) - LAt);
    if llama_decode(FCtx, llama_batch_get_one(@LTokens[LAt], LN)) <> 0 then
      raise Exception.Create('llama_decode failed');
    Inc(LAt, LN);
  end;
  LLogits := llama_get_logits_ith(FCtx, -1);
  if LLogits = nil then
    raise Exception.Create('no logits');
  SetLength(Result, ANOptions);
  LMax := -MaxDouble;
  for I := 0 to ANOptions - 1 do
  begin
    Result[I] := LLogits[FLetters[I]] / T;
    LMax := Max(LMax, Result[I]);
  end;
  LSum := 0;
  for I := 0 to ANOptions - 1 do
  begin
    Result[I] := Exp(Result[I] - LMax);
    LSum := LSum + Result[I];
  end;
  for I := 0 to ANOptions - 1 do
    Result[I] := Result[I] / LSum;
end;

function TLocalJudge.StateJson(AItem: TJevItem): string;
begin
  Result := '{"server": ' + PyJsonStr(Site) + ', "client_ip": ' + PyJsonStr(AItem.Ip) +
    ', "signature_hits": ' + PyJsonStr(AItem.Hits) +
    ', "flagged_requests": ' + PyJsonList(AItem.Flagged) +
    ', "other_recent_requests": ' + PyJsonList(AItem.Earlier) + '}';
end;

function TLocalJudge.Decide(AItems: TList; out AError: string; out ALatencyMs: Int64): Boolean;
var
  LStart: TDateTime;
  LItem: TJevItem;
  LState: string;
  LP: TDoubleArray;
  LOpts: array of string;
  I, J, LBest: Integer;
  LYes, LZ: Double;
begin
  Result := False;
  AError := '';
  LStart := Now;
  try
    for I := 0 to AItems.Count - 1 do
    begin
      if DeciderAbort then
        raise Exception.Create('stopping');
      LItem := TJevItem(AItems[I]);
      { a client with a long history: drop its oldest context until it fits }
      repeat
        LState := StateJson(LItem);
        if Length(LState) < FNCtx * 2 then
          Break;
        if LItem.Earlier.Count > 0 then
          LItem.Earlier.Delete(0)
        else if LItem.Flagged.Count > 1 then
          LItem.Flagged.Delete(0)
        else
          Break;
      until False;
      LP := Readout(Prompt(LState, Question, ['yes', CYes, 'no', CNo]), 2);
      LYes := EnsureRange(LP[0], 1e-4, 1 - 1e-4);
      LZ := Ln(LYes / (1 - LYes)) / NoulT + NoulBias;
      LItem.Malicious := 1 / (1 + Exp(-LZ));
      if AskIntent then
      begin
        SetLength(LOpts, 2 * Length(CIntents));
        for J := 0 to High(CIntents) do
        begin
          LOpts[2 * J] := CIntents[J, 0];
          LOpts[2 * J + 1] := CIntents[J, 1];
        end;
        LP := Readout(Prompt(LState, CIntentQuestion, LOpts), Length(CIntents));
        LBest := 0;
        for J := 1 to High(LP) do
          if LP[J] > LP[LBest] then
            LBest := J;
        LItem.Intent := CIntents[LBest, 0];
      end;
    end;
    Result := True;
  except
    on E: Exception do
      AError := 'local model: ' + E.Message;
  end;
  ALatencyMs := MilliSecondsBetween(Now, LStart);
end;

end.
