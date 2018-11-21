import numpy as np
import matplotlib.pyplot as plt

def graphCDF(pktLens):
    values, base = np.histogram(pktLens, bins=40)
    cumulative = np.cumsum(values)
    plt.plot(base[:-1], cumulative, c='blue')
    plt.show()     
