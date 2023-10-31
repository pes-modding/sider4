#if 0
//
// Generated by Microsoft (R) HLSL Shader Compiler 10.1
//
//
// Buffer Definitions: 
//
// cbuffer ShaderConstants
// {
//
//   float4x4 TransformMatrix;          // Offset:    0 Size:    64
//
// }
//
//
// Resource Bindings:
//
// Name                                 Type  Format         Dim      HLSL Bind  Count
// ------------------------------ ---------- ------- ----------- -------------- ------
// tex0                              texture  float4         buf             t0      1 
// ShaderConstants                   cbuffer      NA          NA            cb0      1 
//
//
//
// Input signature:
//
// Name                 Index   Mask Register SysValue  Format   Used
// -------------------- ----- ------ -------- -------- ------- ------
// POSITIONINDEX            0   xyz         0     NONE   float   xyz 
// GLYPHCOLOR               0   xyzw        1     NONE   float   xyzw
//
//
// Output signature:
//
// Name                 Index   Mask Register SysValue  Format   Used
// -------------------- ----- ------ -------- -------- ------- ------
// SV_Position              0   xyzw        0      POS   float   xyzw
// COLOR                    0   xyzw        1     NONE   float   xyzw
// TEXCOORD                 0   xy          2     NONE   float   xy  
//
gs_4_0
dcl_constantbuffer CB0[4], immediateIndexed
dcl_resource_buffer (float,float,float,float) t0
dcl_input v[1][0].xyz
dcl_input v[1][1].xyzw
dcl_temps 4
dcl_inputprimitive point 
dcl_outputtopology trianglestrip 
dcl_output_siv o0.xyzw, position
dcl_output o1.xyzw
dcl_output o2.xy
dcl_maxout 4
ishl r0.x, v[0][0].z, l(1)
iadd r0.y, r0.x, l(1)
ld r1.xyzw, r0.xxxx, t0.xyzw
ld r0.xyzw, r0.yyyy, t0.xyzw
add r0.xyzw, r0.xyzw, v[0][0].xyxy
mul r2.xyzw, r0.yyyy, cb0[1].xyzw
mad r3.xyzw, cb0[0].xyzw, r0.xxxx, r2.xyzw
mad r2.xyzw, cb0[0].xyzw, r0.zzzz, r2.xyzw
add r2.xyzw, r2.xyzw, cb0[3].xyzw
add r3.xyzw, r3.xyzw, cb0[3].xyzw
mov o0.xyzw, r3.xyzw
mov o1.xyzw, v[0][1].xyzw
mov o2.xy, r1.xyxx
emit 
mov o0.xyzw, r2.xyzw
mov o1.xyzw, v[0][1].xyzw
mov o2.xy, r1.zyzz
emit 
mul r2.xyzw, r0.wwww, cb0[1].xyzw
mad r3.xyzw, cb0[0].xyzw, r0.xxxx, r2.xyzw
mad r0.xyzw, cb0[0].xyzw, r0.zzzz, r2.xyzw
add r0.xyzw, r0.xyzw, cb0[3].xyzw
add r2.xyzw, r3.xyzw, cb0[3].xyzw
mov o0.xyzw, r2.xyzw
mov o1.xyzw, v[0][1].xyzw
mov o2.xy, r1.xwxx
emit 
mov o0.xyzw, r0.xyzw
mov o1.xyzw, v[0][1].xyzw
mov o2.xy, r1.zwzz
emit 
cut 
ret 
// Approximately 33 instruction slots used
#endif

const BYTE g_simpleGS[] =
{
     68,  88,  66,  67,  31,  46, 
    234, 106,  14,  86, 177, 228, 
    243, 186, 211, 240, 152, 117, 
    216,  95,   1,   0,   0,   0, 
     16,   6,   0,   0,   5,   0, 
      0,   0,  52,   0,   0,   0, 
     40,   1,   0,   0, 132,   1, 
      0,   0, 248,   1,   0,   0, 
    148,   5,   0,   0,  82,  68, 
     69,  70, 236,   0,   0,   0, 
      1,   0,   0,   0, 116,   0, 
      0,   0,   2,   0,   0,   0, 
     28,   0,   0,   0,   0,   4, 
     83,  71,   0,   9,   0,   0, 
    196,   0,   0,   0,  92,   0, 
      0,   0,   2,   0,   0,   0, 
      5,   0,   0,   0,   1,   0, 
      0,   0, 255, 255, 255, 255, 
      0,   0,   0,   0,   1,   0, 
      0,   0,  13,   0,   0,   0, 
     97,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      1,   0,   0,   0,   1,   0, 
      0,   0, 116, 101, 120,  48, 
      0,  83, 104,  97, 100, 101, 
    114,  67, 111, 110, 115, 116, 
     97, 110, 116, 115,   0, 171, 
    171, 171,  97,   0,   0,   0, 
      1,   0,   0,   0, 140,   0, 
      0,   0,  64,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0, 164,   0,   0,   0, 
      0,   0,   0,   0,  64,   0, 
      0,   0,   2,   0,   0,   0, 
    180,   0,   0,   0,   0,   0, 
      0,   0,  84, 114,  97, 110, 
    115, 102, 111, 114, 109,  77, 
     97, 116, 114, 105, 120,   0, 
      3,   0,   3,   0,   4,   0, 
      4,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,  77, 105, 
     99, 114, 111, 115, 111, 102, 
    116,  32,  40,  82,  41,  32, 
     72,  76,  83,  76,  32,  83, 
    104,  97, 100, 101, 114,  32, 
     67, 111, 109, 112, 105, 108, 
    101, 114,  32,  49,  48,  46, 
     49,   0,  73,  83,  71,  78, 
     84,   0,   0,   0,   2,   0, 
      0,   0,   8,   0,   0,   0, 
     56,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      3,   0,   0,   0,   0,   0, 
      0,   0,   7,   7,   0,   0, 
     70,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      3,   0,   0,   0,   1,   0, 
      0,   0,  15,  15,   0,   0, 
     80,  79,  83,  73,  84,  73, 
     79,  78,  73,  78,  68,  69, 
     88,   0,  71,  76,  89,  80, 
     72,  67,  79,  76,  79,  82, 
      0, 171, 171, 171,  79,  83, 
     71,  78, 108,   0,   0,   0, 
      3,   0,   0,   0,   8,   0, 
      0,   0,  80,   0,   0,   0, 
      0,   0,   0,   0,   1,   0, 
      0,   0,   3,   0,   0,   0, 
      0,   0,   0,   0,  15,   0, 
      0,   0,  92,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   3,   0,   0,   0, 
      1,   0,   0,   0,  15,   0, 
      0,   0,  98,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   3,   0,   0,   0, 
      2,   0,   0,   0,   3,  12, 
      0,   0,  83,  86,  95,  80, 
    111, 115, 105, 116, 105, 111, 
    110,   0,  67,  79,  76,  79, 
     82,   0,  84,  69,  88,  67, 
     79,  79,  82,  68,   0, 171, 
     83,  72,  68,  82, 148,   3, 
      0,   0,  64,   0,   2,   0, 
    229,   0,   0,   0,  89,   0, 
      0,   4,  70, 142,  32,   0, 
      0,   0,   0,   0,   4,   0, 
      0,   0,  88,   8,   0,   4, 
      0, 112,  16,   0,   0,   0, 
      0,   0,  85,  85,   0,   0, 
     95,   0,   0,   4, 114,  16, 
     32,   0,   1,   0,   0,   0, 
      0,   0,   0,   0,  95,   0, 
      0,   4, 242,  16,  32,   0, 
      1,   0,   0,   0,   1,   0, 
      0,   0, 104,   0,   0,   2, 
      4,   0,   0,   0,  93,   8, 
      0,   1,  92,  40,   0,   1, 
    103,   0,   0,   4, 242,  32, 
     16,   0,   0,   0,   0,   0, 
      1,   0,   0,   0, 101,   0, 
      0,   3, 242,  32,  16,   0, 
      1,   0,   0,   0, 101,   0, 
      0,   3,  50,  32,  16,   0, 
      2,   0,   0,   0,  94,   0, 
      0,   2,   4,   0,   0,   0, 
     41,   0,   0,   8,  18,   0, 
     16,   0,   0,   0,   0,   0, 
     42,  16,  32,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      1,  64,   0,   0,   1,   0, 
      0,   0,  30,   0,   0,   7, 
     34,   0,  16,   0,   0,   0, 
      0,   0,  10,   0,  16,   0, 
      0,   0,   0,   0,   1,  64, 
      0,   0,   1,   0,   0,   0, 
     45,   0,   0,   7, 242,   0, 
     16,   0,   1,   0,   0,   0, 
      6,   0,  16,   0,   0,   0, 
      0,   0,  70, 126,  16,   0, 
      0,   0,   0,   0,  45,   0, 
      0,   7, 242,   0,  16,   0, 
      0,   0,   0,   0,  86,   5, 
     16,   0,   0,   0,   0,   0, 
     70, 126,  16,   0,   0,   0, 
      0,   0,   0,   0,   0,   8, 
    242,   0,  16,   0,   0,   0, 
      0,   0,  70,  14,  16,   0, 
      0,   0,   0,   0,  70,  20, 
     32,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,  56,   0, 
      0,   8, 242,   0,  16,   0, 
      2,   0,   0,   0,  86,   5, 
     16,   0,   0,   0,   0,   0, 
     70, 142,  32,   0,   0,   0, 
      0,   0,   1,   0,   0,   0, 
     50,   0,   0,  10, 242,   0, 
     16,   0,   3,   0,   0,   0, 
     70, 142,  32,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      6,   0,  16,   0,   0,   0, 
      0,   0,  70,  14,  16,   0, 
      2,   0,   0,   0,  50,   0, 
      0,  10, 242,   0,  16,   0, 
      2,   0,   0,   0,  70, 142, 
     32,   0,   0,   0,   0,   0, 
      0,   0,   0,   0, 166,  10, 
     16,   0,   0,   0,   0,   0, 
     70,  14,  16,   0,   2,   0, 
      0,   0,   0,   0,   0,   8, 
    242,   0,  16,   0,   2,   0, 
      0,   0,  70,  14,  16,   0, 
      2,   0,   0,   0,  70, 142, 
     32,   0,   0,   0,   0,   0, 
      3,   0,   0,   0,   0,   0, 
      0,   8, 242,   0,  16,   0, 
      3,   0,   0,   0,  70,  14, 
     16,   0,   3,   0,   0,   0, 
     70, 142,  32,   0,   0,   0, 
      0,   0,   3,   0,   0,   0, 
     54,   0,   0,   5, 242,  32, 
     16,   0,   0,   0,   0,   0, 
     70,  14,  16,   0,   3,   0, 
      0,   0,  54,   0,   0,   6, 
    242,  32,  16,   0,   1,   0, 
      0,   0,  70,  30,  32,   0, 
      0,   0,   0,   0,   1,   0, 
      0,   0,  54,   0,   0,   5, 
     50,  32,  16,   0,   2,   0, 
      0,   0,  70,   0,  16,   0, 
      1,   0,   0,   0,  19,   0, 
      0,   1,  54,   0,   0,   5, 
    242,  32,  16,   0,   0,   0, 
      0,   0,  70,  14,  16,   0, 
      2,   0,   0,   0,  54,   0, 
      0,   6, 242,  32,  16,   0, 
      1,   0,   0,   0,  70,  30, 
     32,   0,   0,   0,   0,   0, 
      1,   0,   0,   0,  54,   0, 
      0,   5,  50,  32,  16,   0, 
      2,   0,   0,   0, 102,  10, 
     16,   0,   1,   0,   0,   0, 
     19,   0,   0,   1,  56,   0, 
      0,   8, 242,   0,  16,   0, 
      2,   0,   0,   0, 246,  15, 
     16,   0,   0,   0,   0,   0, 
     70, 142,  32,   0,   0,   0, 
      0,   0,   1,   0,   0,   0, 
     50,   0,   0,  10, 242,   0, 
     16,   0,   3,   0,   0,   0, 
     70, 142,  32,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      6,   0,  16,   0,   0,   0, 
      0,   0,  70,  14,  16,   0, 
      2,   0,   0,   0,  50,   0, 
      0,  10, 242,   0,  16,   0, 
      0,   0,   0,   0,  70, 142, 
     32,   0,   0,   0,   0,   0, 
      0,   0,   0,   0, 166,  10, 
     16,   0,   0,   0,   0,   0, 
     70,  14,  16,   0,   2,   0, 
      0,   0,   0,   0,   0,   8, 
    242,   0,  16,   0,   0,   0, 
      0,   0,  70,  14,  16,   0, 
      0,   0,   0,   0,  70, 142, 
     32,   0,   0,   0,   0,   0, 
      3,   0,   0,   0,   0,   0, 
      0,   8, 242,   0,  16,   0, 
      2,   0,   0,   0,  70,  14, 
     16,   0,   3,   0,   0,   0, 
     70, 142,  32,   0,   0,   0, 
      0,   0,   3,   0,   0,   0, 
     54,   0,   0,   5, 242,  32, 
     16,   0,   0,   0,   0,   0, 
     70,  14,  16,   0,   2,   0, 
      0,   0,  54,   0,   0,   6, 
    242,  32,  16,   0,   1,   0, 
      0,   0,  70,  30,  32,   0, 
      0,   0,   0,   0,   1,   0, 
      0,   0,  54,   0,   0,   5, 
     50,  32,  16,   0,   2,   0, 
      0,   0, 198,   0,  16,   0, 
      1,   0,   0,   0,  19,   0, 
      0,   1,  54,   0,   0,   5, 
    242,  32,  16,   0,   0,   0, 
      0,   0,  70,  14,  16,   0, 
      0,   0,   0,   0,  54,   0, 
      0,   6, 242,  32,  16,   0, 
      1,   0,   0,   0,  70,  30, 
     32,   0,   0,   0,   0,   0, 
      1,   0,   0,   0,  54,   0, 
      0,   5,  50,  32,  16,   0, 
      2,   0,   0,   0, 230,  10, 
     16,   0,   1,   0,   0,   0, 
     19,   0,   0,   1,   9,   0, 
      0,   1,  62,   0,   0,   1, 
     83,  84,  65,  84, 116,   0, 
      0,   0,  33,   0,   0,   0, 
      4,   0,   0,   0,   0,   0, 
      0,   0,   5,   0,   0,   0, 
     11,   0,   0,   0,   2,   0, 
      0,   0,   0,   0,   0,   0, 
      1,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   1,   0,   0,   0, 
      4,   0,   0,   0,   0,   0, 
      0,   0,   2,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   1,   0, 
      0,   0,   5,   0,   0,   0, 
      4,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0
};
