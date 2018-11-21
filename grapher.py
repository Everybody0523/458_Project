import numpy as np
import matplotlib.pyplot as plt

def graphCDF(data, numBins=40):
    values, base = np.histogram(data, bins=numBins)
    cumulative = np.cumsum(values)
    plt.plot(base[:-1], cumulative, c='blue')
    plt.show()     
