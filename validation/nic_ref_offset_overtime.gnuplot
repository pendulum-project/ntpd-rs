set yrange [-4250:-3150]
set xtics (0, "glitch" 4095)
set xlabel "time (arbitrary)"
set ylabel "offset (ns)"
plot '../meetlogboek/ref-18-03-2022-1446-analysis/nic-offset.dat' using ($1*10.00004010) pt 7 black title "Offset of NIC clock to GM"
