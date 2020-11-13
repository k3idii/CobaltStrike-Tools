"""
  Various CS constant values.
  For clear source code purpose
"""

MAX_ID   = 60
MAX_SIZE = 4096
MAX_REC_SIZE = 0x100

PACKED_CONFIG_PATTERN = """
 00 01  00 01   00 02 ?? ?? 
 00 02  00 01   00 02 ?? ??
 00 03  00 02   00 04
"""

UNPACKED_CONFIG_PATTERN = """
  00 00 00 00   00 00 00 00
  01 00 00 00   ?? 00 00 00
  01 00 00 00   ?? ?? 00 00 
  02 00 00 00   ?? ?? ?? ?? 
  02 00 00 00   ?? ?? ?? ?? 
  01 00 00 00   ?? ?? 00 00
  01 00 00 00   ?? ?? 00 00
  03 00 00 00
"""


OPT_TO_ID = dict(
CFG_BeaconType = 1,
CFG_Port = 2,
CFG_SleepTime = 3,
CFG_MaxGetSize = 4,
CFG_Jitter = 5,
CFG_MaxDNS = 6,
CFG_PublicKey = 7,
CFG_C2Server = 8,
CFG_UserAgent = 9,
CFG_HttpPostUri = 10,
CFG_Malleable_C2_Instructions = 11,
CFG_HttpGet_Metadata = 12,
CFG_HttpPost_Metadata = 13,
CFG_SpawnTo = 14,
CFG_PipeName = 15,
CFG_DNS_Idle = 19,
CFG_DNS_Sleep = 20,
CFG_SSH_Host = 21,
CFG_SSH_Port = 22,
CFG_SSH_Username = 23,
CFG_SSH_Password_Plaintext = 24,
CFG_SSH_Password_Pubkey = 25,
CFG_HttpGet_Verb = 26,
CFG_HttpPost_Verb = 27,
CFG_HttpPostChunk = 28,
CFG_Spawnto_x86 = 29,
CFG_Spawnto_x64 = 30,
CFG_CryptoScheme = 31,
CFG_Proxy_Config = 32,
CFG_Proxy_User = 33,
CFG_Proxy_Password = 34,
CFG_Proxy_Behavior = 35,
CFG_Watermark = 37,
CFG_bStageCleanup = 38,
CFG_bCFGCaution = 39,
CFG_KillDate = 40,
CFG_ObfuscateSectionsInfo = 42,
CFG_bProcInject_StartRWX = 43,
CFG_bProcInject_UseRWX = 44,
CFG_bProcInject_MinAllocSize = 45,
CFG_ProcInject_PrependAppend_x86 = 46,
CFG_ProcInject_PrependAppend_x64 = 47,
CFG_ProcInject_Execute = 51,
CFG_ProcInject_AllocationMethod = 52,
CFG_ProcInject_Stub = 53,
CFG_bUsesCookies = 50,
CFG_HostHeader = 54,
)

ID_TO_OPT = {value: k for k, value in OPT_TO_ID.items()}

BEACON_TYPE = {0x0: "HTTP", 0x1: "Hybrid HTTP DNS",
              0x2: "SMB", 0x4: "TCP", 0x8: "HTTPS", 0x10: "Bind TCP"}
ALLOCA_TYPE = {0: "VirtualAllocEx", 1: "NtMapViewOfSection"}
EXECUTE_TYPE = {0x1: "CreateThread", 0x2: "SetThreadContext",
                0x3: "CreateRemoteThread", 0x4: "RtlCreateUserThread",
                0x5: "NtQueueApcThread", 0x6: None, 0x7: None, 0x8: "NtQueueApcThread-s"}
