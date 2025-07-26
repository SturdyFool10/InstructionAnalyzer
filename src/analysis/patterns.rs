use std::collections::HashMap;

use rayon::iter::{IntoParallelIterator, ParallelIterator};
pub fn get_instruction_patterns() -> HashMap<String, String> {
    let mut patterns = HashMap::new();

    patterns.insert("FPU".to_string(), r"\b(fadd|faddp|fsub|fsubp|fmul|fmulp|fdiv|fdivp|fsqrt|fld|fst|fstp|fild|fist|fistp|fxch|fcom|fcomi|fcomip|fcomp|fcompp|finit|fninit)\b".to_string());
    patterns.insert(
        "VME".to_string(),
        r"\b(vmcall|vmlaunch|vmresume|vmxoff|vtss).\b".to_string(),
    );
    patterns.insert("DE".to_string(), r"\bint\s+0x0|int\s+0x0e\b".to_string());
    patterns.insert("PSE".to_string(), r"\b(lgdt|sgdt|lidt|sidt)\b".to_string());
    patterns.insert("TSC".to_string(), r"\b(rdtsc|rdtscp)\b".to_string());
    patterns.insert("MSR".to_string(), r"\b(rdmsr|wrmsr)\b".to_string());
    patterns.insert(
        "PAE".to_string(),
        r"\b(lcr[0-7]|mov\s+cr[0-7])\b".to_string(),
    );
    patterns.insert("MCE".to_string(), r"\b(mcerr|mc[rw]x?)\b".to_string());
    patterns.insert("CX8".to_string(), r"\b(cmpxchg|cmpxchg8b)\b".to_string());
    patterns.insert("APIC".to_string(), r"\b(xapic|mxapic|apicid)\b".to_string());
    patterns.insert("SEP".to_string(), r"\b(sysenter|sysexit)\b".to_string());
    patterns.insert("MTRR".to_string(), r"\b(rdwrmtrr|wrmtrr)\b".to_string());
    patterns.insert("PGE".to_string(), r"\b(invpcid)\b".to_string());
    patterns.insert("MCA".to_string(), r"\b(mca_init|mcg_)\b".to_string());
    patterns.insert("CMOV".to_string(), r"\b(cmovae|cmovb|cmove|cmovg|cmovge|cmovl|cmovle|cmovna|cmovnb|cmovno|cmovnp|cmovns|cmovo|cmovp|cmovpe|cmovs|cmovz)\b".to_string());
    patterns.insert("PAT".to_string(), r"\b(wbinvd)\b".to_string());
    patterns.insert("CLFLUSH".to_string(), r"\b(clflush)\b".to_string());
    patterns.insert("MMX".to_string(), r"\b(paddb|paddw|paddd|pmullw|pmaxsb|pmaxsw|pmaxub|pmaxuw|pminsb|pminsw|pminub|pminuw|pshufb|pshufw|pshufd|por|pand|pxor|movq|emms|maskmovq)\b".to_string());
    patterns.insert("FXSR".to_string(), r"\b(fxsave|fxrstor)\b".to_string());
    patterns.insert("SSE".to_string(), r"(?:\b(addps|subps|mulps|divps|sqrtps|movaps|movups|andps|orps|xorps|shufps|unpck[hlu]ps|cmpps|comiss|ucomiss|cvt\w*ps)\b|\baddps\b|\bsubps\b|\bmulps\b|\bdivps\b|\bsqrtps\b|\brsqrtps\b|\bmaxps\b|\bminps\b|\bmovaps\b|\bmovups\b|\bcmpps\b|\bshufps\b|\bunpckhps\b|\bunpcklps\b|\bxmm[0-9]+\b|\bmovss\b|\baddss\b|\bsubss\b|\bmulss\b|\bdivss\b|\bcmpss\b|\bcomiss\b|\bucomiss\b|\bcvtsi2ss\b|\bcvtss2si\b|\bcvttss2si\b)".to_string());
    patterns.insert("SSE2".to_string(), r"(?:\b(addpd|subpd|mulpd|divpd|sqrtpd|movapd|movupd|andpd|orpd|xorpd|cmppd|unpck[hlu]pd|comisd|ucomisd|cvt\w*pd|movsd)\b|\bmovapd\b|\bmovupd\b|\baddpd\b|\bsubpd\b|\bmulpd\b|\bdivpd\b|\bsqrtpd\b|\bmaxpd\b|\bminpd\b|\bcmppd\b|\bshufpd\b|\bunpckhpd\b|\bunpcklpd\b|\bmovsd\b|\baddsd\b|\bsubsd\b|\bmulsd\b|\bdivsd\b|\bcmpsd\b|\bcomisd\b|\bucomisd\b|\bcvtsi2sd\b|\bcvtsd2si\b|\bcvttsd2si\b|\bcvtps2pd\b|\bcvtpd2ps\b|\bcvtdq2ps\b|\bcvtps2dq\b|\bcvttps2dq\b|\bpand\b|\bpandn\b|\bpor\b|\bpxor\b|\bpadd[bwdq]\b|\bpsub[bwdq]\b|\bpmulhw\b|\bpmullw\b|\bpsll[wdq]\b|\bpsrl[wdq]\b|\bpsra[wd]\b|\bpacksswb\b|\bpackssdw\b|\bpackuswb\b|\bpunpckh[bwdq]\b|\bpunpckl[bwdq]\b|\bpcmpeq[bwd]\b|\bpcmpgt[bwd]\b|\bpmovmskb\b|\bpextrw\b|\bpinsrw\b|\bpshufd\b|\bpshufhw\b|\bpshuflw\b)".to_string());
    patterns.insert("SSE3".to_string(), r"(?:\b(addsubps|haddps|hsubps|lddqu)\b|\baddsubps\b|\baddsubpd\b|\bhaddps\b|\bhsubps\b|\bhaddpd\b|\bhsubpd\b|\bmovsldup\b|\bmovshdup\b|\bmovddup\b|\blddqu\b|\bmonitor\b|\bmwait\b)".to_string());
    patterns.insert("SSSE3".to_string(), r"(?:\b(hadd[bw|ps]|hs*sub[bw|ps]|palignr|psign[bw|d]|pmulhrw|pmaddubsw)\b|\bpabs[bdw]\b|\bpsign[bdw]\b|\bpalignr\b|\bpshufb\b|\bpmulhrsw\b|\bpmaddubsw\b|\bphsub[wd]\b|\bphsubsw\b|\bphadd[wd]\b|\bphaddsw\b)".to_string());
    patterns.insert(
        "PCLMULQDQ".to_string(),
        r"\b(pclmulqdq|pclmul)\b".to_string(),
    );
    patterns.insert("MONITOR".to_string(), r"\b(monitor|mwait)\b".to_string());
    patterns.insert("DsCpl".to_string(), r"\b(rdtscp)\b".to_string());
    patterns.insert(
        "VMX".to_string(),
        r"\b(vmcall|vmclear|vmlaunch|vmresume|vmread|vmwrite|vmxon)\b".to_string(),
    );
    patterns.insert("SMX".to_string(), r"\b(wbinvd|vmfunc)\b".to_string());
    patterns.insert("EST".to_string(), r"\b(enclv|encl[uv])\b".to_string());
    patterns.insert("TM2".to_string(), r"\b(tm\s*;?{0,1})\b".to_string());
    patterns.insert("CnxtId".to_string(), r"\b(stac|clac)\b".to_string());
    patterns.insert(
        "SSE41".to_string(),
        r"\b(insertps|dpps|mpsadbw|blendps)\b".to_string(),
    );
    patterns.insert(
        "SSE42".to_string(),
        r"\b(crc32|pcmpistr[a-z])\b".to_string(),
    );
    patterns.insert("MOVBE".to_string(), r"\b(movbe)\b".to_string());
    patterns.insert("POPCNT".to_string(), r"\b(popcnt)\b".to_string());
    patterns.insert(
        "AES".to_string(),
        r"\b(aesenc|aesdec|aesenclast|aesdeclast|aesimc|aeskeygenassist)\b".to_string(),
    );
    patterns.insert(
        "XSAVE".to_string(),
        r"\b(xsave|xrestore|xsaveopt)\b".to_string(),
    );
    patterns.insert("OSXSAVE".to_string(), r"\b(xsaves|xsavec)\b".to_string());
    patterns.insert("AVX".to_string(), r"(?:\b(vaddps|vsubps|vmulps|vdivps|vaddpd|vsubpd|vmulpd|vdivpd|vxorps|vandps|vorps|vsqrtps|vsqrtpd|vshufps|vshufpd)\b|\bymm[0-9]+\b|\bvmovaps\b|\bvmovups\b|\bvaddps\b|\bvsubps\b|\bvmulps\b|\bvdivps\b|\bvxorps\b|\bvorps\b|\bvandps\b|\bvandnps\b|\bvmaxps\b|\bvminps\b|\bvbroadcast(ss|sd|f128)\b|\bvinsertf128\b|\bvextractf128\b|\bvmaskmovps\b|\bvmaskmovpd\b|\bvperm2f128\b|\bvcmpps\b|\bvroundps\b|\bvsqrtps\b|\bvrsqrtps\b|\bvrcpps\b|\bvmovapd\b|\bvmovupd\b|\bvaddpd\b|\bvsubpd\b|\bvmulpd\b|\bvdivpd\b|\bvxorpd\b|\bvorpd\b|\bandpd\b|\bvandnpd\b|\bvmaxpd\b|\bvminpd\b|\bvcmppd\b|\bvroundpd\b|\bvsqrtpd\b|\bvaddss\b|\bvsubss\b|\bvmulss\b|\bdivss\b|\bvsqrtss\b|\bvaddsd\b|\bvsubsd\b|\bvmulsd\b|\bdivsd\b|\bvsqrtsd\b|\bvzeroupper\b|\bvzeroall\b)".to_string());
    patterns.insert(
        "F16C".to_string(),
        r"\b(vcvtphps2pq|vcvtpdpq2ps)\b".to_string(),
    );
    patterns.insert("RDRAND".to_string(), r"\b(rdrand)\b".to_string());
    patterns.insert("RDSEED".to_string(), r"\b(rdseed)\b".to_string());
    patterns.insert(
        "FSGSBASE".to_string(),
        r"\b(rdfsbase|rdgsbase|wrfsbase|wrgsbase)\b".to_string(),
    );
    patterns.insert("BMI1".to_string(), r"\b(andn|bextr|t1mskc)\b".to_string());
    patterns.insert(
        "BMI2".to_string(),
        r"\b(movntdqa|pdep|pext|shrx|sarx|rorx)\b".to_string(),
    );
    patterns.insert("HLE".to_string(), r"\b(xbegin|xend|xabort)\b".to_string());
    patterns.insert("RTM".to_string(), r"\b(xbegin|xend|xabort)\b".to_string());
    patterns.insert("SMEP".to_string(), r"\b(wrsmep)\b".to_string());
    patterns.insert("SMAP".to_string(), r"\b(wrsmapp)\b".to_string());
    patterns.insert(
        "ERMS".to_string(),
        r"\b(rep stos|rep movs|rep cmps|rep scas)\b".to_string(),
    );
    patterns.insert("INVPCID".to_string(), r"\b(invpcid)\b".to_string());
    patterns.insert(
        "MPX".to_string(),
        r"\b(bndldx|bndstx|bndcl|bndcn|bndmov)\b".to_string(),
    );
    patterns.insert("ADX".to_string(), r"\b(adcx|adox)\b".to_string());
    patterns.insert(
        "SHA".to_string(),
        r"\b(sha1rnds4|sha256rnds2|sha256msg1|sha256msg2)\b".to_string(),
    );
    patterns.insert("CLFLUSHOPT".to_string(), r"\b(clflushopt)\b".to_string());
    patterns.insert("CLWB".to_string(), r"\b(clwb)\b".to_string());
    patterns.insert("PREFETCHWT1".to_string(), r"\b(prefetchwt1)\b".to_string());
    patterns.insert(
        "PREFETCHW".to_string(),
        r"\b(prefetchw|3dnowprefetch)\b".to_string(),
    );
    patterns.insert(
        "AVX512F".to_string(),
        r"\b(vaddps|vaddpd|vmulps|vmulpd|vsubps|vsubpd|vdivps|vdivpd|vxorps)\b".to_string(),
    );
    patterns.insert(
        "AVX512DQ".to_string(),
        r"\b(vcvtdq2ps|vcmpeq|vcmpgtq)\b".to_string(),
    );
    patterns.insert(
        "AVX512IFMA".to_string(),
        r"\b(vfmadd132ps|vfmadd132pd|vfmadd213ps|vfmadd213pd|vfmadd231ps|vfmadd231pd)\b"
            .to_string(),
    );
    patterns.insert(
        "AVX512CD".to_string(),
        r"\b(vptestmd|vptestmq|vptestnmd|vptestnmq)\b".to_string(),
    );
    patterns.insert(
        "AVX512BW".to_string(),
        r"\b(vpackss[bwd]|vpackus[bwd]|vpunpckhbw|vpunpcklbw)\b".to_string(),
    );
    patterns.insert(
        "AVX512VL".to_string(),
        r"\b(vmovd|vpinsrb|vextracti128|vinserti128|vpmovsx[bwd]|vpmovzx[bwd])\b".to_string(),
    );
    patterns.insert(
        "AVX512VBMI".to_string(),
        r"\b(vperm2f128|vpermi2ps|vgatherdp)\b".to_string(),
    );
    patterns.insert(
        "AVX512VBMI2".to_string(),
        r"\b(vpermt2ps|vpermt2pd|vpermt2w|vpermt2d)\b".to_string(),
    );
    patterns.insert(
        "AVX512PKU".to_string(),
        r"\b(pku|pconfig|pcommit)\b".to_string(),
    );
    patterns.insert(
        "AVX512ER".to_string(),
        r"(?:\bvexp2p[sd]\b|\bvrcp28p[sd][sd]?\b|\bvrsqrt28p[sd][sd]?\b)".to_string(),
    );
    patterns.insert(
        "MisalignSse".to_string(),
        r"\b(misaligned_mov)\b".to_string(),
    );
    patterns.insert(
        "D3DNOWEXT".to_string(),
        r"\b(prefetchw|3dnowprefetch)\b".to_string(),
    );
    patterns.insert("D3DNOW".to_string(), r"\b(pfadd|pfacc|pfchg|pfmax|pfmin|pfrcp|pfrcpit1|pfrcpit2|pfrsqit1|pfrsqrt|pfsqrt|pfmul)\b".to_string());

    patterns.insert("AVX2".to_string(), r"(?:\bvp(erm|gather|broadcast|blend|mask)|\bvextract[if][123]\d\d\b|\bvinsert[if][123]\d\d\b|\bvpbroadcast[bwdq]\b|\bvbroadcasti128\b|\bvinserti128\b|\bvextracti128\b|\bvgather[dq]p[ds]\b|\bvpgather[dq][dq]\b|\bvpmaskmov[dq]\b|\bvperm[dpqst]\b|\bvperm2i128\b|\bvpsll[vdq]\b|\bvpsrl[vdq]\b|\bvpsra[vd]\b|\bvpadd[bwdq]\b|\bvpsub[bwdq]\b|\bvpmull[dw]\b|\bvpmulh[wu]w\b|\bvpmulhrsw\b|\bvpmuldq\b|\bvpmuludq\b|\bvpmaddwd\b|\bvpmaddubsw\b|\bvpand\b|\bvpandn\b|\bvpor\b|\bvpxor\b|\bvpack[su][sw][bw]\b|\bvpcmp[eg][tq][bwdq]\b|\bvpunpck[lh][bwdq]\b|\bvpalignr\b|\bvpshuf[bd]\b|\bvpabs[bdw]\b|\bvpsign[bdw]\b)".to_string());
    patterns.insert("FMA".to_string(), r"(?:\bvfm(add|sub|add(sub)|sub(add))[0-9]+[sdp][sd]\b|\bvfnm(add|sub)[0-9]+[sdp][sd]\b|\bvfmadd[123]+(13|31|23|32)[ps][sdy]\b|\bvfmsub[123]+(13|31|23|32)[ps][sdy]\b|\bvfnmadd[123]+(13|31|23|32)[ps][sdy]\b|\bvfnmsub[123]+(13|31|23|32)[ps][sdy]\b)".to_string());
    let mut keys: Vec<&String> = patterns.keys().collect();
    keys.sort();
    let sorted_patterns: HashMap<String, String> = keys
        .into_par_iter()
        .map(|k| (k.clone(), patterns[k].clone()))
        .collect();
    sorted_patterns
}
