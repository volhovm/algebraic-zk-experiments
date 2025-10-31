#!/usr/bin/env python
# coding: utf-8

# In[1]:


#from IPython.display import display, HTML
#display(HTML("<style>div.output_scroll { height: 100em; }</style>"))
#from IPython.display import display, HTML
#display(HTML("<style>.container { width:100% !important; }</style>"))

import itertools
from itertools import chain
import random

def defvars(label, n):
    return list(var(label + '_%d' % i) for i in range(n))

def defpoly_from_basis(label, basis):
    coeffs = defvars(label,len(basis))
    poly = sum(c*x for c,x in zip(coeffs,basis))
    return (coeffs,poly)

def defpoly(label, d):
    return defpoly_from_basis(label, list(x**i for i in range(d+1)))

def concat(lists):
    return list(itertools.chain.from_iterable(lists))

# For given d, let P = prod_{j=0}^{d-1} (X-j), then this function
# returns the coefficient of P corresponding to X^i for given i
def stirling(d,i):
    if i == 0:
        return 0
    stirlingR = PolynomialRing(SR,'stir')
    p = prod(stirlingR.0-j for j in range(d))
    print(p)
    print(p.coefficients(stirlingR.0)[i-1])

def v_coeff(i,j,x):
    return binomial(i,j)*(x**(i-j))

#print(v_coeff(1,1,var('bla')))
#print(concat([[5,6],[6],[2,1,1]]))

def subs_vec(vec,subsmap):
    return vector([e.subs(subsmap) for e in vec])

def subs_mat(mat,subsmap):
    return Matrix([[e.subs(subsmap) for e in row] for row in mat])

# Vertically stacks two vectors
def stack(vec1,vec2):
    return vector(list(vec1) + list(vec2))



def print_coeff(eq,mon):
    show(mon)
    if mon == 1:
        print(eq.constant_coefficient())
    else:
        print(eq.monomial_coefficient(mon))
    print("--------------------------")


deg = 2
dim = 2


var('alpha')
var('w0')
var('w1')
f1_vars = [[[var('f1_%d_%d_%d' % (k,i,j)) for j in range(deg)] for i in range(deg)] for k in range(dim)]
f2_vars = [[var('f2_%d_%d' % (k,i)) for i in range(deg)] for k in range(dim)]
g1_vars = [var('g1_%d' % i) for i in range(deg)]
g2_vars = [var('g2_%d' % i) for i in range(deg)]
g3_vars = [var('g2_%d' % i) for i in range(deg)]
t_vars = [var('t_%d' % i) for i in range(deg)]


def f1(x,y):
    return vector([sum([sum([f1_vars[k][i][j] * x^i * y^j for j in range(deg)]) for i in range(deg)]) for k in range(dim)])

def f2(y):
    return vector([sum([f2_vars[k][i] * y^i for i in range(deg)]) for k in range(dim)])

def g1(a):
    return sum([g1_vars[i] * a^i for i in range(deg)])

def g2(a):
    return sum([g2_vars[i] * a^i for i in range(deg)])

def g3(a):
    return sum([g3_vars[i] * a^i for i in range(deg)])

def t(a):
    #return sum([t_vars[i] * a^i for i in range(deg)])
    return a

eq1 = f1(w0,w1) * (-1) * g1(alpha) + g2(alpha) * f2(w1) - f1(-w0, t(alpha) * w1)
eq2 = f2(w1) * g3(alpha) - f2(t(alpha) * w1)

print(eq1)
print(eq2)
for i in range(dim):
    print(" ", i, ": ", eq1[i].full_simplify())
for i in range(dim):
    print(" ", i, ": ", eq2[i].full_simplify())



f1_vars_flat = [el for x in f1_vars for y in x for el in y]
f2_vars_flat = [el for x in f2_vars for el in x]

sols = solve(list(eq1) + list(eq2), f1_vars_flat + f2_vars_flat + g1_vars + g2_vars + g3_vars, solution_dict=True)

print(sols)
