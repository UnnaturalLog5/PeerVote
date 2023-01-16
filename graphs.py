#! /usr/env/python

import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

df = pd.read_csv("perf0.csv")

df.t1 = df.t1 / 1e6
df.t2 = df.t2 / 1e6


plt.figure()
plt.title("Time to Intialize Election (10 total nodes)")

ax = sns.barplot(df[df.t1 > 0], y="t1", x="n", palette="pastel")

ax.set_xlabel("Number of Mixnet Nodes")
ax.set_ylabel("Time [s]")

for i, line in enumerate(ax.get_lines()):
    line.set_color("grey")

plt.savefig("t1.png", dpi=300)

plt.figure()
plt.title("Time to Conclude Election (Mix and Tally) (10 total nodes)")

ax = sns.barplot(df[df.t2 > 0], y="t2", x="n", palette="pastel")

ax.set_xlabel("Number of Mixnet Nodes")
ax.set_ylabel("Time [s]")

for i, line in enumerate(ax.get_lines()):
    line.set_color("grey")

plt.savefig("t2.png", dpi=300)