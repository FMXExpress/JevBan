unit Ban.Llama;

(* The slice of the llama.cpp C API (llama.h) that a decision readout needs:
   load a GGUF model, tokenize, decode a prompt, read the logits at the last
   position. Loaded at run time with dynlibs, so jevban still starts (and
   falls back to its rules) on a machine without the libraries.

   Record layouts are copied from memagent's Mem.Llama, which pins them to
   LLAMA_TAG and checks them against the sizes the C compiler reported; the
   release ships libraries built from that tag. *)

{$mode objfpc}{$H+}
{$packrecords C}

interface

uses
  SysUtils, Math, DynLibs, ctypes;

const
  LLAMA_TAG = 'b11985';

type
  PLlamaModel = Pointer;
  PLlamaContext = Pointer;
  PLlamaVocab = Pointer;
  PLlamaMemory = Pointer;
  TLlamaToken = Int32;
  PLlamaToken = ^TLlamaToken;
  TLlamaTokens = array of TLlamaToken;

  TLlamaModelParams = record
    devices: Pointer;
    tensor_buft_overrides: Pointer;
    n_gpu_layers: Int32;
    split_mode: Int32;
    load_mode: Int32;
    lazy_mode: Int32;
    main_gpu: Int32;
    tensor_split: PSingle;
    progress_callback: Pointer;
    progress_callback_user_data: Pointer;
    kv_overrides: Pointer;
    vocab_only: Boolean;
    check_tensors: Boolean;
    use_extra_bufts: Boolean;
    no_host: Boolean;
    no_alloc: Boolean;
    load_mtp: Boolean;
  end;

  TLlamaContextParams = record
    n_ctx: UInt32;
    n_batch: UInt32;
    n_ubatch: UInt32;
    n_seq_max: UInt32;
    n_rs_seq: UInt32;
    n_outputs_max: UInt32;
    n_outputs_max_per_seq: UInt32;
    n_threads: Int32;
    n_threads_batch: Int32;
    ctx_type: Int32;
    rope_scaling_type: Int32;
    pooling_type: Int32;
    attention_type: Int32;
    flash_attn_type: Int32;
    rope_freq_base: Single;
    rope_freq_scale: Single;
    yarn_ext_factor: Single;
    yarn_attn_factor: Single;
    yarn_beta_fast: Single;
    yarn_beta_slow: Single;
    yarn_orig_ctx: UInt32;
    defrag_thold: Single;
    cb_eval: Pointer;
    cb_eval_user_data: Pointer;
    type_k: Int32;
    type_v: Int32;
    moe_cache_size: csize_t;
    abort_callback: Pointer;
    abort_callback_data: Pointer;
    embeddings: Boolean;
    offload_kqv: Boolean;
    no_perf: Boolean;
    op_offload: Boolean;
    swa_full: Boolean;
    kv_unified: Boolean;
    samplers: Pointer;
    n_samplers: csize_t;
    ctx_other: Pointer;
  end;

  TLlamaBatch = record
    n_tokens: Int32;
    token: PLlamaToken;
    embd: PSingle;
    pos: PInt32;
    n_seq_id: PInt32;
    seq_id: Pointer;
    logits: PShortInt;
  end;

  TGgmlLogCallback = procedure(ALevel: Int32; AText: PAnsiChar; AUserData: Pointer); cdecl;
  TGgmlLoadAll = procedure(ADir: PAnsiChar); cdecl;

var
  llama_backend_init: procedure; cdecl;
  llama_log_set: procedure(ACallback: TGgmlLogCallback; AUserData: Pointer); cdecl;
  llama_model_default_params: function: TLlamaModelParams; cdecl;
  llama_context_default_params: function: TLlamaContextParams; cdecl;
  llama_model_load_from_file: function(APath: PAnsiChar; AParams: TLlamaModelParams): PLlamaModel; cdecl;
  llama_model_free: procedure(AModel: PLlamaModel); cdecl;
  llama_init_from_model: function(AModel: PLlamaModel; AParams: TLlamaContextParams): PLlamaContext; cdecl;
  llama_free: procedure(ACtx: PLlamaContext); cdecl;
  llama_model_get_vocab: function(AModel: PLlamaModel): PLlamaVocab; cdecl;
  llama_model_desc: function(AModel: PLlamaModel; ABuf: PAnsiChar; ASize: csize_t): Int32; cdecl;
  llama_vocab_n_tokens: function(AVocab: PLlamaVocab): Int32; cdecl;
  llama_tokenize: function(AVocab: PLlamaVocab; AText: PAnsiChar; ATextLen: Int32; ATokens: PLlamaToken;
    ANTokensMax: Int32; AAddSpecial, AParseSpecial: Boolean): Int32; cdecl;
  llama_batch_get_one: function(ATokens: PLlamaToken; ANTokens: Int32): TLlamaBatch; cdecl;
  llama_decode: function(ACtx: PLlamaContext; ABatch: TLlamaBatch): Int32; cdecl;
  llama_get_memory: function(ACtx: PLlamaContext): PLlamaMemory; cdecl;
  llama_memory_clear: procedure(AMem: PLlamaMemory; AData: Boolean); cdecl;
  llama_get_logits_ith: function(ACtx: PLlamaContext; AIdx: Int32): PSingle; cdecl;

{ loads the libraries from ADir ('' = the loader's search path); raises }
procedure LlamaLoad(const ADir: string);
procedure LlamaMaskFpu;
function LlamaLibNames: TStringArray;

implementation

var
  GHandles: array of TLibHandle;
  GLoaded: Boolean;

function LlamaLibNames: TStringArray;
begin
  (* ggml first: preloading the dependencies by full path makes the loader
     find them by soname when libllama asks, whatever its RUNPATH says *)
  {$if defined(windows)}
  Result := ['ggml-base.dll', 'ggml-cpu.dll', 'ggml.dll', 'llama.dll'];
  {$elseif defined(darwin)}
  Result := ['libggml-base.dylib', 'libggml-cpu.dylib', 'libggml.dylib', 'libllama.dylib'];
  {$else}
  Result := ['libggml-base.so', 'libggml-cpu.so', 'libggml.so', 'libllama.so'];
  {$endif}
end;

{$if (SizeOf(TLlamaModelParams) <> 80) or (SizeOf(TLlamaContextParams) <> 168) or (SizeOf(TLlamaBatch) <> 56)}
  {$error Ban.Llama record layout does not match llama.h}
{$endif}

procedure LlamaMaskFpu;
begin
  { ggml's kernels rely on the C default: inf and NaN, no trap }
  SetExceptionMask([exInvalidOp, exDenormalized, exZeroDivide, exOverflow, exUnderflow, exPrecision]);
end;

procedure LlamaLoad(const ADir: string);
var
  LName, LPath, LMissing: string;
  H, LLlama: TLibHandle;
  LoadAll: TGgmlLoadAll;

  procedure Bind(var AProc; const ASym: string);
  begin
    Pointer(AProc) := GetProcedureAddress(LLlama, ASym);
    if Pointer(AProc) = nil then
      LMissing := LMissing + ' ' + ASym;
  end;

begin
  if GLoaded then
    Exit;
  LlamaMaskFpu;
  LLlama := NilHandle;
  for LName in LlamaLibNames do
  begin
    if ADir <> '' then
      LPath := IncludeTrailingPathDelimiter(ADir) + LName
    else
      LPath := LName;
    H := LoadLibrary(LPath);
    if H = NilHandle then
    begin
      { a static or merged build only ships libllama }
      if LName <> LlamaLibNames[High(LlamaLibNames)] then
        Continue;
      raise Exception.CreateFmt('cannot load %s (%s)', [LPath, GetLoadErrorStr]);
    end;
    SetLength(GHandles, Length(GHandles) + 1);
    GHandles[High(GHandles)] := H;
    LLlama := H;
  end;
  LMissing := '';
  Bind(llama_backend_init, 'llama_backend_init');
  Bind(llama_log_set, 'llama_log_set');
  Bind(llama_model_default_params, 'llama_model_default_params');
  Bind(llama_context_default_params, 'llama_context_default_params');
  Bind(llama_model_load_from_file, 'llama_model_load_from_file');
  Bind(llama_model_free, 'llama_model_free');
  Bind(llama_init_from_model, 'llama_init_from_model');
  Bind(llama_free, 'llama_free');
  Bind(llama_model_get_vocab, 'llama_model_get_vocab');
  Bind(llama_model_desc, 'llama_model_desc');
  Bind(llama_vocab_n_tokens, 'llama_vocab_n_tokens');
  Bind(llama_tokenize, 'llama_tokenize');
  Bind(llama_batch_get_one, 'llama_batch_get_one');
  Bind(llama_decode, 'llama_decode');
  Bind(llama_get_memory, 'llama_get_memory');
  Bind(llama_memory_clear, 'llama_memory_clear');
  Bind(llama_get_logits_ith, 'llama_get_logits_ith');
  if LMissing <> '' then
    raise Exception.Create('llama.cpp library is not ' + LLAMA_TAG + '-compatible, missing:' + LMissing);
  (* a build with GGML_BACKEND_DL ships one CPU library per instruction set
     (libggml-cpu-haswell, -skylakex, -zen4, ...) and picks the best at run
     time: on AVX-512 hardware 1.56x faster than the portable AVX2 build. In a
     build without it, this finds nothing to load and is harmless. *)
  for H in GHandles do
  begin
    LoadAll := TGgmlLoadAll(GetProcedureAddress(H, 'ggml_backend_load_all_from_path'));
    if Assigned(LoadAll) then
    begin
      if ADir <> '' then
        LoadAll(PAnsiChar(AnsiString(ExcludeTrailingPathDelimiter(ADir))))
      else
        LoadAll(nil);
      Break;
    end;
  end;
  GLoaded := True;
end;

end.
