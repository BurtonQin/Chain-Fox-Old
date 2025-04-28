import pandas as pd
import scipy.stats as st
import sys

if __name__ == '__main__':
  for filename in sys.argv[1:]:
    df = pd.read_csv(filename)

    for column in df.columns:
      # Creates 95% confidence interval for population mean
      mean_val = df[column].mean()
      (low, _) = st.t.interval(confidence=0.95, df=len(df)-1, loc=mean_val, scale=st.sem(df[column]))
      print(f'{filename}: {column}: {mean_val:.3f} +- {mean_val - low:.3f}')