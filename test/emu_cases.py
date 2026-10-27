"""Hand-computed emulator cases for the Si4440 8051 variant.  Every expectation is worked out by hand from the 8051
instruction set manual (never from the module's output).

CASES entries: (name, code-bytes-hex, init, expect[, start[, stop-offset]]).  The code is placed at `start` (default: an
automatically allocated address at 0x6000+) and runs until PC reaches start+len(code) (or the given stop address).
init / expect items (comma separated):  ACC B SP DPTR PC R0..R7 =hex,  PSW&mask=hex (compare the masked bits only),
INTMEM#n:addr=hex and RAM#n:addr=hex (n bytes, big-endian).
PSW bits: CY 80, AC 40, F0 20, RS1 10, RS0 08, OV 04, F1 02, P 01.  Flag masks used below: c4 = CY|AC|OV.
Comments give the working.
"""

CASES = [
    # ---- arithmetic and flags
    ('add_overflow_halfcarry',            # 7F + 01 = 80: no carry, carry out of bit 3 (F+1), signed overflow (+127+1)
     '2401', 'ACC=7f,PSW=0', 'ACC=80,PSW&c4=44'),
    ('add_carry_out',                      # FF + 01 = 100: A=00, CY, AC (F+1), no overflow (-1+1)
     '2401', 'ACC=ff,PSW=0', 'ACC=0,PSW&c4=c0'),
    ('add_two_negatives',                  # 80 + 80 = 100: A=00, CY, no AC (0+0), OV (-128-128)
     '2480', 'ACC=80,PSW=0', 'ACC=0,PSW&c4=84'),
    ('addc_carry_in_wraps_operand',        # FF + 00 + CY(1) = 100: A=00, CY, AC (F+0+1), no OV
     '3400', 'ACC=ff,PSW=80', 'ACC=0,PSW&c4=c0'),
    ('addc_carry_in_overflow',             # 7F + 00 + 1 = 80: CY=0, AC=1, OV=1
     '3400', 'ACC=7f,PSW=80', 'ACC=80,PSW&c4=44'),
    ('subb_halfborrow_overflow',           # 80 - 01 - 0 = 7F: no borrow, borrow from bit 4 (0<1), OV (-128-1)
     '9401', 'ACC=80,PSW=0', 'ACC=7f,PSW&c4=44'),
    ('subb_borrow_in',                     # 00 - 00 - CY(1) = FF: borrow out, AC borrow, no OV
     '9400', 'ACC=0,PSW=80', 'ACC=ff,PSW&c4=c0'),
    ('subb_register_no_borrow',            # 25 - 14 = 11 (R3 = 14), CY = 0
     '9b', 'ACC=25,R3=14,PSW=0', 'ACC=11,PSW&c4=0'),
    ('mul_ab',                             # 0x50 * 0x0A = 800 = 0x0320: A=20, B=03, OV (B != 0), CY cleared
     'a4', 'ACC=50,B=a,PSW=80', 'ACC=20,B=3,PSW&c4=4'),
    ('div_ab',                             # 251 / 18 = 13 rem 17: A=0D, B=11, CY=OV=0
     '84', 'ACC=fb,B=12,PSW=84', 'ACC=d,B=11,PSW&c4=0'),
    ('div_by_zero_flags',                  # division by zero: OV set, CY clear (A, B undefined on the chip)
     '84', 'ACC=10,B=0,PSW=80', 'PSW&c4=4'),
    ('da_low_nibble',                      # 45 + 38 = 7D; DA: low nibble D > 9 -> +6 = 83 (BCD 45+38 = 83), CY=0
     '2438d4', 'ACC=45,PSW=0', 'ACC=83,PSW&80=0'),
    ('da_carry_out',                       # 99 + 01 = 9A; DA: low A > 9 -> +6 = A0; high A > 9 -> +60 = 100: A=00, CY (BCD 100)
     '2401d4', 'ACC=99,PSW=0', 'ACC=0,PSW&80=80'),
    ('inc_dec_no_flags',                   # INC A of FF = 00 and DEC A of 00 = FF leave PSW alone
     '0414', 'ACC=ff,PSW=a4', 'ACC=ff,PSW&e4=a4'),
    # ---- logic, rotates
    ('anl_orl_xrl_do_not_touch_psw',       # F0 & 3C = 30, | 03 = 33, ^ FF = CC; PSW user flags F0 and bit 1 untouched
     '543c440364ff', 'ACC=f0,PSW=22', 'ACC=cc,PSW&e6=22'),
    ('swap',                               # SWAP 3C = C3
     'c4', 'ACC=3c', 'ACC=c3'),
    ('cpl_a',                              # CPL 3C = C3
     'f4', 'ACC=3c', 'ACC=c3'),
    ('clr_a',
     'e4', 'ACC=3c', 'ACC=0'),
    ('rlc',                                # 81 with CY=0: A = 02, CY = 1 (old bit 7)
     '33', 'ACC=81,PSW=0', 'ACC=2,PSW&80=80'),
    ('rrc',                                # 01 with CY=1: A = 80, CY = 1 (old bit 0)
     '13', 'ACC=1,PSW=80', 'ACC=80,PSW&80=80'),
    ('rl',                                 # RL 81 = 03 (bit 7 rotates into bit 0)
     '23', 'ACC=81', 'ACC=3'),
    ('rr',                                 # RR 03 = 81 (bit 0 rotates into bit 7)
     '03', 'ACC=3', 'ACC=81'),
    # ---- data movement and addressing modes
    ('mov_direct_register_alias',          # MOV R5,#AA (7D AA) then MOV A,05h (E5 05): direct address 5 is R5
     '7daae505', '', 'ACC=aa,R5=aa'),
    ('indirect_store_reaches_register',    # R1=03: MOV @R1,A stores into internal RAM 03 = R3
     'f7', 'ACC=66,R1=3', 'R3=66,INTMEM#1:3=66'),
    ('indirect_load',                      # R0=30, [30]=12: MOV A,@R0
     'e6', 'R0=30,INTMEM#1:30=12', 'ACC=12'),
    ('mov_direct_direct',                  # 85 src dst: MOV 31h,30h
     '853031', 'INTMEM#1:30=5c', 'INTMEM#1:31=5c'),
    ('xch_a_indirect',                     # XCH A,@R0: A=11, [40]=22 -> A=22, [40]=11
     'c6', 'ACC=11,R0=40,INTMEM#1:40=22', 'ACC=22,INTMEM#1:40=11'),
    ('xchd',                               # A=3C, [40]=F5: swap low nibbles: A=35, [40]=FC
     'd6', 'ACC=3c,R0=40,INTMEM#1:40=f5', 'ACC=35,INTMEM#1:40=fc'),
    ('mov_dptr_inc_carry',                 # 90 12FF: DPTR=12FF; INC DPTR = 1300
     '9012ffa3', '', 'DPTR=1300'),
    ('movc_a_dptr',                        # DPTR=6800, A=3: A = code[6803] = AB
     '93', 'DPTR=6800,ACC=3,RAM#1:6803=ab', 'ACC=ab'),
    ('movc_a_pc',                          # at S: 83 (MOVC A,@A+PC); A=2 reads S+1+2 = S+3 = CD
     '83', 'ACC=2,RAM#1:{S+3}=cd', 'ACC=cd'),
    ('movx_dptr_write',                    # MOVX @DPTR,A: external data and code share RAM space
     'f0', 'DPTR=1234,ACC=77', 'RAM#1:1234=77'),
    ('movx_dptr_read',
     'e0', 'DPTR=1234,RAM#1:1234=99', 'ACC=99'),
    ('movx_ri_page_50',                    # MOVX @R0,A with XPAGE 0x50: address 5010
     'f2', 'R0=10,ACC=5a', 'RAM#1:5010=5a'),
    ('movx_ri_read',
     'e3', 'R1=ff,RAM#1:50ff=c3', 'ACC=c3'),
    ('mov_sp_then_push',                   # MOV SP,#40 (75 81 40); PUSH ACC (C0 E0): [41] = ACC, SP = 41
     '758140c0e0', 'ACC=7e,SP=10', 'SP=41,INTMEM#1:41=7e'),
    ('push_pop',                           # PUSH ACC / POP B
     'c0e0d0f0', 'ACC=5a,SP=30', 'B=5a,SP=30,INTMEM#1:31=5a'),
    ('pop_into_register_bank',             # POP 02h (D0 02): R2 = [SP], SP-1
     'd002', 'SP=33,INTMEM#1:33=9d', 'R2=9d,SP=32'),
    # ---- bit operations
    ('setb_clr_cpl_ram_bit',               # bit 13h = byte 22h bit 3: SETB -> 08; CPL -> 00; CPL -> 08; CLR -> 00 ; SETB again
     'd213b213b213c213d213', 'INTMEM#1:22=0', 'INTMEM#1:22=8'),
    ('jbc_taken',                          # JBC 13h,+2: bit set -> cleared and jumps over 2 bytes
     '1013020000', 'INTMEM#1:22=ff', 'INTMEM#1:22=f7', None, 5),
    ('jb_not_taken_jnb_taken',             # JB 13h not taken (bit clear) falls through to JNB 13h,+2 (taken)
     '2013043013020000', 'INTMEM#1:22=0', '-', None, 8),
    ('anl_c_not_bit',                      # C=1, bit 13h = 1: C = 1 & !1 = 0
     'b013', 'PSW=80,INTMEM#1:22=8', 'PSW&80=0'),
    ('orl_c_bit_mov_c_bit',                # ORL C,13h with C=0: C = 1; MOV 14h,C: bit 14h = byte 22 bit 4 = 1 -> [22] = 18
     '72139214', 'PSW=0,INTMEM#1:22=8', 'PSW&80=80,INTMEM#1:22=18'),
    ('acc_and_b_bits',                     # SETB E3h sets ACC bit 3; CLR F7h clears B bit 7
     'd2e3c2f7', 'ACC=0,B=ff', 'ACC=8,B=7f'),
    ('psw_bits',                           # SETB D2h (OV); CPL D7h (CY)
     'd2d2b2d7', 'PSW=0', 'PSW&c4=84'),
    ('parity_in_psw',                      # ACC = 07 has three set bits: P = 1; MOV B,PSW (85 D0 F0) with CY set -> 81
     '85d0f0', 'ACC=7,PSW=80', 'B=81'),
    ('parity_even',                        # ACC = 03: P = 0
     '85d0f0', 'ACC=3,PSW=0', 'B=0'),
    ('jb_p_flag',                          # JB D0h (P),+2: ACC=01 -> P=1 -> taken
     '20d0020000', 'ACC=1,PSW=0', '-', None, 5),
    # ---- control flow
    ('djnz_loop',                          # MOV R2,#3; INC A; DJNZ R2,-3: three iterations
     '7a0304dafd', 'ACC=0', 'ACC=3,R2=0'),
    ('cjne_less_taken',                    # 5 < 9: CY=1, branch taken (+2)
     'b40902', 'ACC=5,PSW=0', 'PSW&80=80', None, 5),
    ('cjne_greater_taken',                 # 9 > 5: CY=0, taken
     'b40502', 'ACC=9,PSW=80', 'PSW&80=0', None, 5),
    ('cjne_equal_not_taken',               # equal: falls through, CY=0
     'b40502', 'ACC=5,PSW=80', 'PSW&80=0', None, 3),
    ('jz_jnz_jc_jnc_taken',                # A=0: JZ +2 taken; JNZ not; chain: 60 02 / 00 00 /
     '600200007002', 'ACC=0', '-', None, 6),
    ('sjmp_backward',                      # SJMP to itself minus 0: 80 FE would loop; 80 02 skips two bytes
     '8002', '', '-', None, 4),
    ('lcall_ret',                          # LCALL sub; INC A; (stop). sub: INC A; RET.  A: 0 -> 2
     '1240060400000422', 'ACC=0,SP=20', 'ACC=2,SP=20,INTMEM#2:21=0340', 0x4000, 4),
    ('acall_pushes_return_address',        # ACALL 4777 from 4400: pushes 4402 (low byte first), PC = 4777
     'f177', 'SP=20', 'PC=4777,SP=22,INTMEM#2:21=0244', 0x4400, 0x4777 - 0x4400),
    ('ajmp_page',                          # AJMP 4555 from 4300 (page 4000): opcode = (5<<5)|01 = A1, byte 55
     'a155', '', 'PC=4555', 0x4300, 0x4555 - 0x4300),
    ('jmp_a_dptr',                         # JMP @A+DPTR: DPTR=4600, A=10 -> 4610
     '73', 'DPTR=4600,ACC=10', 'PC=4610', 0x4500, 0x4610 - 0x4500),
    ('ret_pops_address',                   # RET: PC = ([22] << 8) | [21] = 0x1234; SP 22 -> 20
     '22', 'SP=22,INTMEM#2:21=3412', 'PC=1234,SP=20', 0x4200, 0x1234 - 0x4200),
    ('reti_pops_address',
     '32', 'SP=22,INTMEM#2:21=5678', 'PC=7856,SP=20', 0x4200, 0x7856 - 0x4200),
    # ---- a deliberately wrong expectation: must be reported
    ('XFAIL_add_wrong_result',
     '2401', 'ACC=7f,PSW=0', 'ACC=81'),
    ('XFAIL_wrong_flag',
     '2401', 'ACC=ff,PSW=0', 'ACC=0,PSW&c4=44'),
]
