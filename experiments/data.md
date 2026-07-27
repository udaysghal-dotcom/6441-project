The following is the data I used for section 4.4 - Experimental Evaluation and Results. 
Data was acquired by running the experiment scripts, and copying the results that were outputed in the terminal. You can recreate the experiments by running: "python3 experiments/exp_*"   

=== BATCH-GCD VS NAIVE PAIRWISE SCALING ===
Corpus_Size     Naive_Time_Sec  Batch_Time_Sec  Speedup
64      0.002802        0.000740        3.79x
128     0.011499        0.002447        4.70x
256     0.045452        0.008386        5.42x
512     0.187509        0.030877        6.07x
1024    0.733798        0.118120        6.21x
2048    2.920335        0.442265        6.60x

=== WEAK PRNG YIELD EXPERIMENT ===
Total_Moduli    Factored_Moduli Factored_Percent
50      49      98.0%


=== RNG ENTROPY VS SHARED-PRIME FACTORIZATION RATE ===
Pool_Size       Entropy_Bits    Factored_Fraction       Sharing_Estimate
50      5.64    1.0000  0.9821
100     6.64    0.8500  0.8647
200     7.64    0.6250  0.6312
500     8.97    0.2750  0.3286
1000    9.97    0.1300  0.1805
2000    10.97   0.0700  0.0947
5000    12.29   0.0200  0.0390


=== FERMAT FACTORIZATION COST VS PRIME GAP (256-bit n) ===
Gap_Exponent_Target     Actual_Gap_Bits Iterations      Feasible
2^60    61      1       True
2^61    62      1       True
2^62    63      1       True
2^63    64      1       True
2^64    65      1       True
2^65    66      1       True
2^66    67      4       True
2^67    68      15      True
2^68    69      33      True
2^69    70      209     True
2^70    71      663     True
2^71    72      2725    True
2^72    73      9937    True
2^73    74      48065   True
2^74    75      203117  True
2^75    76      986006  True
2^76    77      3845874 True


=== HÅSTAD BROADCAST RECOVERY THRESHOLD ===
Exponent_e      Num_Recipients  Recovery_Success        Threshold_Met
3       1       0       False
3       2       0       False
3       3       1       True
3       4       1       True
5       1       0       False
5       2       0       False
5       3       0       False
5       4       0       False
5       5       1       True
5       6       1       True


=== WIENER ATTACK SUCCESS BOUNDARY (512-bit n) ===
Theoretical Bound: d < (1/3)*n^(1/4) = 126.42 bits
d_Bits  Successes       Total_Trials    Success_Rate    Under_Theoretical_Bound
108     6       6       1.0000  True
111     6       6       1.0000  True
114     6       6       1.0000  True
117     6       6       1.0000  True
120     6       6       1.0000  True
123     6       6       1.0000  True
126     6       6       1.0000  True
129     0       6       0.0000  False
132     0       6       0.0000  False
135     0       6       0.0000  False
138     0       6       0.0000  False
141     0       6       0.0000  False
144     0       6       0.0000  False


=== RSA BUILD / BREAK / FIX MATRIX ===
Attack_Name     Weak_Key_Result Hardened_Key_Result
Fermat Factorisation    breaks  blocked
Common-Modulus  breaks  blocked
Hastad Broadcast        breaks  blocked
Wiener Attack   breaks  blocked
Textbook Malleability   breaks  blocked
Batch-GCD       breaks  blocked
