key
00000000  38 66 27 c2 89 1f ce 8b  c2 b9 13 57 c2 ae 7d c2  |8f'........W..}.|
00000010  be c2 90 09 c3 a0 06 21  30 0a                    |.......!0.|

setlocal_3
getlocal_2
pushbyte 8
subtract
li32
getlocal_3
si32
getlocal_3
findproperty Qname(PackageNamespace("C_Run"),"ESP")
swap
setproperty Qname(PackageNamespace("C_Run"),"ESP")
findpropstrict Multiname("F_puts",[PackageNamespace("C_Run"),PackageNamespace("C_Run_D_3A__2F_software_2F_Tools_2F_CrossBridge_2F_cygwin_2F_tmp_2F_cc5pzkZ7_2E_o_3A_686d8495_2D_693d_2D_4fb1_2D_bfad_2D_9c265c55fcf2"),PackageNamespace("avm2.intrinsics.memory"),PackageNamespace("MyCPP"),PackageInternalNs("MyCPP"),PrivateNamespace("FilePrivateNS:alctmp-tHrv4g"),PackageNamespace(""),Namespace("http://adobe.com/AS3/2006/builtin")])
callpropvoid Multiname("F_puts",[PackageNamespace("C_Run"),PackageNamespace("C_Run_D_3A__2F_software_2F_Tools_2F_CrossBridge_2F_cygwin_2F_tmp_2F_cc5pzkZ7_2E_o_3A_686d8495_2D_693d_2D_4fb1_2D_bfad_2D_9c265c55fcf2"),PackageNamespace("avm2.intrinsics.memory"),PackageNamespace("MyCPP"),PackageInternalNs("MyCPP"),PrivateNamespace("FilePrivateNS:alctmp-tHrv4g"),PackageNamespace(""),Namespace("http://adobe.com/AS3/2006/builtin")]) 0
getlocal_3
pushbyte 16
add
convert_i


s[5] += 5;
s[1] -= 5;
s[4] += 2

package MyCPP
{
   import C_Run.*;
   import C_Run_D_3A__2F_software_2F_Tools_2F_CrossBridge_2F_cygwin_2F_tmp_2F_cc5pzkZ7_2E_o_3A_686d8495_2D_693d_2D_4fb1_2D_bfad_2D_9c265c55fcf2.L__2E_str10;
   import C_Run_D_3A__2F_software_2F_Tools_2F_CrossBridge_2F_cygwin_2F_tmp_2F_cc5pzkZ7_2E_o_3A_686d8495_2D_693d_2D_4fb1_2D_bfad_2D_9c265c55fcf2.L__2E_str7;
   import C_Run_D_3A__2F_software_2F_Tools_2F_CrossBridge_2F_cygwin_2F_tmp_2F_cc5pzkZ7_2E_o_3A_686d8495_2D_693d_2D_4fb1_2D_bfad_2D_9c265c55fcf2.L__2E_str8;
   import C_Run_D_3A__2F_software_2F_Tools_2F_CrossBridge_2F_cygwin_2F_tmp_2F_cc5pzkZ7_2E_o_3A_686d8495_2D_693d_2D_4fb1_2D_bfad_2D_9c265c55fcf2.L__2E_str9;
   import avm2.intrinsics.memory.li32;
   import avm2.intrinsics.memory.si32;
   import com.adobe.flascc.CModule;
   
   public function check(src:String) : void
   {
      var _as3ReturnValue:* = undefined;
      var ebp:* = 0;
      var key:int = 0;
      var iv:int = 0;
      var i0:int = 0;
      var esp:* = int(ESP);
      ebp = esp;
      esp = int(esp - 48);
      si32(L__2E_str7,ebp - 4);
      si32(0,src_str);
      ESP = esp & -16;
      i0 = CModule.mallocString(src);
      si32(i0,src_str);    
      i0 = li32(src_str);
      esp = int(esp - 16);
      si32(i0,esp);
      ESP = esp;
      F_puts();
      esp = int(esp + 16);
      int(eax);
      key = ebp - 24;
      iv = ebp - 40;

      // key
      si32(-536244034,ebp - 12);
      si32(2108577555,ebp - 16);
      si32(-1182021347,ebp - 20);
      si32(-1993905352,ebp - 24);

      // iv
      si32(252579084,ebp - 28);
      si32(185207048,ebp - 32);
      si32(117835012,ebp - 36);
      si32(50462976,ebp - 40);

      i0 = li32(src_str);
      esp = int(esp - 16);
      si32(i0,esp);
      ESP = esp;
      F_strlen();
      esp = int(esp + 16);
      i0 = eax;
      si32(i0,src_len);
      esp = int(esp - 16);
      si32(key,esp + 4);                 // key
      si32(L__2E_str8,esp);              // str_bf
      ESP = esp;
      F__Z9brainfuckPKcPh();
      esp = int(esp + 16);
      esp = int(esp - 16);
      si32(64,esp);
      ESP = esp;
      F_malloc();
      esp = int(esp + 16);
      i0 = eax;
      si32(i0,buf);                      // buf = malloc(64)
      i0 = li32(buf);
      esp = int(esp - 16);
      si32(64,esp + 8);
      si32(0,esp + 4);
      si32(i0,esp);
      ESP = esp;
      Fmemset();
      esp = int(esp + 16);
      i0 = li32(src_str);
      var i5:int = li32(buf);
      esp = int(esp - 32);
      si32(iv,esp + 16);                  // iv
      si32(key,esp + 12);                 // key
      si32(int(li32(src_len)),esp + 8);   // src_len
      si32(i0,esp + 4);                   // src_str
      si32(i5,esp);                       // buf
      ESP = esp;
      F__Z25AES128_CBC_encrypt_bufferPhS_jPKhS1_();
      esp = int(esp + 32);
      i0 = li32(ebp - 4);
      esp = int(esp - 16);
      si32(64,esp + 8);                   // 64
      si32(int(li32(buf)),esp + 4);       // buf
      si32(i0,esp);                       // str7
      ESP = esp;
      F_memcmp();
      esp = int(esp + 16);
      i0 = eax;
      if(i0 != 0)
      {
         esp = int(esp - 16);
         si32(L__2E_str10,esp);
         ESP = esp;
         F_puts();
         esp = int(esp + 16);
         int(eax);
      }
      else
      {
         esp = int(esp - 16);
         si32(L__2E_str9,esp);
         ESP = esp;
         F_puts();
         esp = int(esp + 16);
         int(eax);
      }
      i0 = li32(buf);
      esp = int(esp - 16);
      si32(i0,esp);
      ESP = esp;
      F_free();
      esp = int(esp + 16);
      esp = ebp;
      ESP = esp;
      return _as3ReturnValue;
   }
}

package C_Run_D_3A__2F_software_2F_Tools_2F_CrossBridge_2F_cygwin_2F_tmp_2F_cc5pzkZ7_2E_o_3A_686d8495_2D_693d_2D_4fb1_2D_bfad_2D_9c265c55fcf2
{
  [Csym(".rodata.str1.16")]
  public const L__2E_str7:int = S__2E_rodata_2E_str1_2E_16 + 144;
}

package C_Run_D_3A__2F_software_2F_Tools_2F_CrossBridge_2F_cygwin_2F_tmp_2F_cc5pzkZ7_2E_o_3A_686d8495_2D_693d_2D_4fb1_2D_bfad_2D_9c265c55fcf2
{
   public const S__2E_rodata_2E_str1_2E_16:int = modSects[".rodata.str1.16"][0];
}

".rodata.str1.16":[CModule.allocDataSect(modPkgName,".rodata.str1.16",263,16),263],

Õa:b9b5±ód/3B#Ól&«*?G(´F¥	!¬º´³(NÀ¼ïSüC1\Ú|Ð

