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


# In[3]:


def print_coeff(eq,mon):
    show(mon)
    if mon == 1:
        print(eq.constant_coefficient())
    else:
        print(eq.monomial_coefficient(mon))
    print("--------------------------")


# In[4]:


nx = 6            # number of instance elements
ntheta = 5        # number of theta elems
n = nx + ntheta   # number of equations
m = 15             # number of witness elements
nh = 6            # number of random bases

hs = [var('H%d' % i) for i in range(nh)]
rr_vars = [var('rr_%d' % i) for i in range(m)]


# # For uBlu
# d = 3
# n = 3*d+4
# nx = 3 + 2*d
# m = 2*d+8

# hs = [var('H0'),var('H1')] + list(var('W%d' % (i+1)) for i in range(d)) # Some hash-to-curve elements
# nh = len(hs)

def generate_random_language():
    mat = [[0 for j in range(m)] for i in range(n)]
    for i in range(n):
        for j in range(m):
            choice = random.random()
            if choice < 0.6:
                mat[i][j] = lambda inst: 0
            elif choice < 0.95:
                mat[i][j] = lambda inst: 1
            else:
                ix = random.randint(0, nx-1)
                mat[i][j] = lambda inst: inst[ix]

    vec = [0 for i in range(n-nx)]
    for i in range(n-nx):
        # Each element is randomly either 0, 1, or inst[i]
        choice = random.random()
        if choice < 0.33:
            vec[i] = lambda inst: 0
        elif choice < 0.66:
            vec[i] = lambda inst: 1
        else:
            ix = random.randint(0, nx-1)
            vec[i] = lambda inst: inst[ix]

    def random_M(inst):
        mat_instantiated = [[mat[i][j](inst) for j in range(m)] for i in range(n)]
        return Matrix(mat_instantiated)

    def random_theta(inst):
        vec_instantiated = [vec[i](inst) for i in range(n-nx)]
        return vector(vec_instantiated)

    return random_M, random_theta


# Generate matrices automatically
# M, theta = generate_random_language()

# # Manual generation:
# def M(inst):
#     mat = [[0 for j in range(m)] for i in range(n)]
#     # mat[0][0] = 1         # x1 = G^w1
#     # mat[1][1] = hs[0]     # x2 = H^w2
#     # mat[2][1] = inst[0]   # x3 = x1^w2 = G^{w1 w2}

#     # mat[3][2] = 1         # x3 = G^{w3}

#     # mat[4][0] = inst[1]   # x3^{-1} = x2^w1 (H^-1 G^-1)^w3
#     # mat[4][2] = (-1 - hs[0])

#     # Powers of 1 witness plus 2nd witness mixed in, no blinders
#     mat[0][0] = 1         # x1 = G^w1
#     mat[1][0] = inst[0]   # x2 = x1^w1 = G^{w1^2}
#     mat[2][1] = inst[1]   # x3 = x2^w2 = G^{w1^2 w2}

#     return Matrix(mat)

# def theta(inst):
#     vec = [0 for i in range(n-nx)]

#     # vec[0] = inst[2]
#     # vec[1] = -inst[2]

#     return vector(vec)


# 1 -> (*-1) -1 -> (*-1) 1

# X -> (*5) Y -> (*5) X

# X^7 - 4 * X^3 - 2 = 0

# X^4 - 1   => would capture roots of unity of deg 4 if they exist

# 7, 13,    (X - 7)(X - 13) = 0
# X          X + alpha = Y mod p, Y + alpha = X mod p

#  X         A X + B = Y,   A Y + B = X
#            (A - 1) (X + Y) + 2 B = 0   mod p ?
#                             2 ((p-1)/2)
#            (X+Y)^{-1} (X+Y)  - 1  = 0

def Mtheta(inst):

    mat = [[0 for j in range(m)] for i in range(n)]
    vec = [0 for i in range(n - nx)]


    ############ Diffie Hellman w/o additives

    # mat[0][0] = 1
    # mat[0][3] = hs[0]

    # mat[1][1] = 1
    # mat[1][4] = hs[1]

    # mat[2][2] = 1
    # mat[2][5] = hs[2]

    # mat[3][1] = inst[0]
    # mat[3][2] = -1
    # mat[3][6] = -hs[0]

    # vec[0] = 0

    ########## forcing upd 1 to w0 and w1

    # # x1 = G^w1 H^w3
    # mat[0][0] = 1
    # mat[0][2] = hs[0]

    # mat[1][1] = 1    # x2 = G^w2

    # # x3 = (x1)^w2 (x2)^w2 = G^{w1 w2 + w2^2} H^w3w2
    # mat[2][1] = inst[0] + inst[1]

    # # # # x4 = x3^{w1 + w2} = G^{(w1^2 + w2^2) (w1 + w2)}
    # # mat[3][0] = inst[2] #+ hs[0]
    # # mat[3][1] = inst[2] #+ hs[1]

    # # 1 = inst[0]^w1 H^w4 = G^{w1^2} H^w2w1 H^w4 => w4 = -w3w1
    # mat[3][0] = inst[0]
    # mat[3][3] = hs[0]
    # vec[0] = 1


    ###########  mult <-> add upd

    # x0 = G^w0 H^w2
    # x1 = G^w1 H1^w4
    # x2 = G^{w0 w1^2 + w1} H2^w11
    # x3 = G^{13 w1} H2^{25 w5^2}
    # x4 = H3^w5 H4^w10
    # 1 = inst[0]^w0 H^w3 = G^{w0^2} H^w0w1 H^w3
    # 0 = x1^w1 G^-w6 H1^-w7
    # 0 = x0^w6 G^-w8 H^-w9
    # 0 = x4^w5 H3^-w11 H4^-w12


    #    given a = 50,
    # x0^{-1} = G^-w0 H^-w2
    # x1^{a^2} = G^{a^2 w1} H1^{a^2 w4}
    # x2^{-a^4} x3^{2500} = G^{(-w0) (a^2 w1)^2 - a^4 w1 + 2501 * 2500 w1} H2^{-a^4 w11 + 5000 * 2500 w5^2}
    #                = G^{(-w0) (a^2 w1)^2 + (6252500-a^4) w1} H2^{(12500000 - a^4) w5^2}
    #               ...
    #       for a = 50, 6252500 - a^4 = 2500 = a^2
    #                   12500000 - a^4 = a^4
    #               ...
    #                = G^{(-w0) (a^2 w1)^2 + a^4 w1} H2^{a^4 w5^2}
    #
    # x3^{a^2} = G^{13 (a^2 w1)} H2^{25 (a w5)^2}
    # x4 = H3^w5 H4^w10
    # 1 = inst[0]^w0 H^w3 = G^{w0^2} H^w0w1 H^w3
    # 0 = x1^w1 G^-w6 H1^-w7
    # 0 = x0^w6 G^-w8 H^-w9
    # 0 = x4^w5 H3^-w11 H4^-w12

    #mat[0][0] = 1
    #mat[0][2] = hs[0]

    #mat[1][1] = 1
    #mat[1][4] = hs[1]

    #mat[2][1] = 1
    #mat[2][8] = 1
    #mat[2][11] = hs[2]

    ## the "additive add-on" that one needs to slap on
    #mat[3][1] = 13
    #mat[3][11] = 25 * hs[2]

    #mat[4][5] = hs[3]
    #mat[4][10] = hs[4]

    ## => w4 = -w3w1
    ## => w0^2 = 1
    #mat[5][0] = inst[0]
    #mat[5][3] = hs[0]
    #vec[0] = 1

    ## => w6 = w1 * w1
    ## => w7 = w4 * w1
    #mat[6][1] = inst[1]
    #mat[6][6] = -1
    #mat[6][7] = -hs[1]
    #vec[1] = 0

    ## => w8 = w0 w1^2
    ## => w9 = w2 w1^2
    #mat[7][6] = inst[0]
    #mat[7][8] = -1
    #mat[7][9] = -hs[0]
    #vec[2] = 0

    ## => w11 = w5^2
    ## => w12 = w10 * w5
    #mat[8][5] = inst[4]
    #mat[8][11] = -hs[3]
    #mat[8][12] = -hs[4]
    #vec[3] = 0


    #!lang
    ######### "only adding w0 -> w0 + alpha * w1" language


    # x0 = G^w0 H0^w2
    # x1 = G^w1 H0^w3
    # x2 = x0^{w0} H0^{-w7} H2^w0 H3^w4     = G^{w0^2 + w0}   H2^w0  H3^w4
    # x3 = G^{2*w11 + w1} H2^w1 H3^w5       = G^{2*w1w0 + w1} H2^w1  H3^w5
    # x4 = G^{w9} H3^w6                     = G^{w1^2}               H3^w6
    # x5 = G^{w9} H4^w1                     = G^{w1^2}               H4^w1

    # introduce vars: ...
    # 0 = x0^{w2} G^{-w7} H0^{-w8}      => w7 = w0w2   w8 = w2^2
    # 0 = x1^{w1} G^{-w9} H0^{-w10}     => w9 = w1^2   w10 = w3w1
    # 0 = x0^{w1} G^{-w11} H0^{-w12}    => w11 = w0w1  w12 = w2w1
    # 0 = x1^{w2} G^{-w12} H0^{-w13}    => w13 = w2w3
    # 0 = x1^{w3} G^{-w10} H0^{-w14}    => w14 = w3^2
    # 0 = x0^{w3} G^{-w15} H0^{-w13}    => w15 = w0w3


    # Updating:
    # x0' = x0 x1    = G^{w0+w1} H0^{w2+w3}
    # x1' = x1       = G^w1 H0^w3
    # x2' = x2 x3 x4 = G^{(w0^2 + 2w1w0 + w1^2) + (w0 + w1)} H2^{w0+w1} H3^{w4+w5+w6}
    # x3' = x3 x4^2  = G^{2*w1(w0 + w1) + w1} H2^w1 H3^{w5 + 2 w6}
    # x4' = x4       = G^{w9} H3^w6
    # x5' = x5       = G^{w9} H4^w1

    # w0'  = w0 + w1
    # w1'  = w1
    # w2'  = w2 + w3
    # w3'  = w3
    # w4'  = w4 + w5 + w6
    # w5'  = w5 + 2 w6
    # w6'  = w6
    # w7'  = w7 + w12 + w15 + w10 = w0w2 + w1w2 + w0w3 + w1w3 = (w0+w1) (w2+w3)
    # w8'  = w8 + 2 w13 + w14 = (w2 + w3)^2
    # w9'  = w9
    # w10' = w10
    # w11' = w11 + w9 = w0w1 + w1^2 = (w0+w1)w1
    # w12' = w12 + w10 = w2w1 + w3w1 = (w2+w3)w1
    # w13' = w13 + w14 = w2w3 + w3^2 = (w2+w3)w3
    # w14' = w14
    # w15' = w15 + w10 = w0w3 + w1w3 = (w0+w1)w3


    #mat[0][0] = 1
    #mat[0][2] = hs[0]

    #mat[1][1] = 1
    #mat[1][3] = hs[0]

    #mat[2][0] = inst[0] + hs[2] + 1
    #mat[2][7] = -hs[0]
    #mat[2][4] = hs[3]

    #mat[3][1] = 1 + hs[2]
    #mat[3][11] = 2
    #mat[3][5] = hs[3]

    #mat[4][9] = 1
    #mat[4][6] = hs[3]

    #mat[5][9] = 1
    #mat[5][1] = hs[4]

    #mat[6][2] = inst[0]
    #mat[6][7] = -1
    #mat[6][8] = -hs[0]
    #vec[0] = 0

    #mat[7][1] = inst[1]
    #mat[7][9] = -1
    #mat[7][10] = -hs[0]
    #vec[1] = 0

    #mat[8][1] = inst[0]
    #mat[8][11] = -1
    #mat[8][12] = -hs[0]
    #vec[2] = 0

    #mat[9][2] = inst[1]
    #mat[9][12] = -1
    #mat[9][13] = -hs[0]
    #vec[3] = 0

    #mat[10][3] = inst[1]
    #mat[10][10] = -1
    #mat[10][14] = -hs[0]
    #vec[4] = 0

    #mat[11][3] = inst[0]
    #mat[11][15] = -1
    #mat[11][13] = -hs[0]
    #vec[5] = 0

    #!lang
    ######### "only adding w0 -> w0 + alpha * w1" language
    ######### BUT ONLY WHEN KNOWING w0


    # x0 = G^w0 H0^w2
    # x1 = G^w1 H0^w3
    # x2 = x0^{w0} H0^{-w7} H2^w0 H3^w4     = G^{w0^2 + w0}   H2^w0  H3^w4
    # x3 = G^{2*w11 + w1} H2^w1 H3^w5       = G^{2*w1w0 + w1} H2^w1  H3^w5
    # x4 = G^{w9} H3^w6                     = G^{w1^2}               H3^w6
    # x5 = G^{w9} H4^w1                     = G^{w1^2}               H4^w1

    # introduce vars: ...
    # 0 = x0^{w2} G^{-w7} H0^{-w8}      => w7 = w0w2   w8 = w2^2
    # 0 = x1^{w1} G^{-w9} H0^{-w10}     => w9 = w1^2   w10 = w3w1
    # 0 = x0^{w1} G^{-w11} H0^{-w12}    => w11 = w0w1  w12 = w2w1
    # 0 = x1^{w2} G^{-w12} H0^{-w13}    => w13 = w2w3
    # 0 = x1^{w3} G^{-w10} H0^{-w14}    => w14 = w3^2
    # 0 = x0^{w3} G^{-w15} H0^{-w13}    => w15 = w0w3


    # Updating:
    # x0' = x0 x1    = G^{w0+w1} H0^{w2+w3}
    # x1' = x1       = G^w1 H0^w3
    # x2' = x2 x3 x4 = G^{(w0^2 + 2w1w0 + w1^2) + (w0 + w1)} H2^{w0+w1} H3^{w4+w5+w6}
    # x3' = x3 x4^2  = G^{2*w1(w0 + w1) + w1} H2^w1 H3^{w5 + 2 w6}
    # x4' = x4       = G^{w9} H3^w6
    # x5' = x5       = G^{w9} H4^w1

    # w0'  = w0 + w1
    # w1'  = w1
    # w2'  = w2 + w3
    # w3'  = w3
    # w4'  = w4 + w5 + w6
    # w5'  = w5 + 2 w6
    # w6'  = w6
    # w7'  = w7 + w12 + w15 + w10 = w0w2 + w1w2 + w0w3 + w1w3 = (w0+w1) (w2+w3)
    # w8'  = w8 + 2 w13 + w14 = (w2 + w3)^2
    # w9'  = w9
    # w10' = w10
    # w11' = w11 + w9 = w0w1 + w1^2 = (w0+w1)w1
    # w12' = w12 + w10 = w2w1 + w3w1 = (w2+w3)w1
    # w13' = w13 + w14 = w2w3 + w3^2 = (w2+w3)w3
    # w14' = w14
    # w15' = w15 + w10 = w0w3 + w1w3 = (w0+w1)w3



    mat[0][0] = 1
    mat[0][2] = hs[0]

    mat[1][1] = 1
    mat[1][3] = hs[0]

    mat[2][0] = inst[0] + hs[2] + 1
    mat[2][7] = -hs[0]
    mat[2][4] = hs[3]

    mat[3][1] = 1 + hs[2]
    mat[3][11] = 2
    mat[3][5] = hs[3]

    mat[4][9] = 1
    mat[4][6] = hs[3]

    mat[5][9] = 1
    mat[5][1] = hs[4]

    mat[6][2] = inst[0]
    mat[6][7] = -1
    mat[6][8] = -hs[0]
    vec[0] = 0

    mat[7][1] = inst[1]
    mat[7][9] = -1
    mat[7][10] = -hs[0]
    vec[1] = 0

    mat[8][1] = inst[0]
    mat[8][11] = -1
    mat[8][12] = -hs[0]
    vec[2] = 0

    mat[9][2] = inst[1]
    mat[9][12] = -1
    mat[9][13] = -hs[0]
    vec[3] = 0

    mat[10][3] = inst[1]
    mat[10][10] = -1
    mat[10][14] = -hs[0]
    vec[4] = 0

    #mat[11][3] = inst[0]
    #mat[11][15] = -1
    #mat[11][13] = -hs[0]
    #vec[5] = 0



    #!lang
    ########## not upd w/o secret, upd w/ secret


    ## M[inst][wit] = base

    ## x0 = G^w0 H0^w2
    #mat[0][0] = 1
    #mat[0][2] = hs[0]

    ## x1 = G^w1 H0^w3
    #mat[1][1] = 1
    #mat[1][3] = hs[0]

    ## x2 = (x0 * x1 * H2)^w0
    #mat[2][0] = inst[0] + inst[1] + hs[2]
    #mat[2][1] = inst[0]

    ## x3 = (x1* H3)^w1
    #mat[3][1] = inst[1] + hs[3]

    #!lang
    ########### this lang prevents w0 upd EVEN when w0 is known

    # M[inst][wit] = base

    # Can we simplify this?

    # x0 = G^w0 H0^w2
    # x1 = (x0 H1)^w1 H2^w3   = G^{w0w1} H0^{w2w1} H1^w1 H2^w3
    # x2 = H3^w3 H4^w4
    # x3 = (x2 H5)^w3         = H3^{w3^2} H5^w3 H4^{w4w3}


    #mat[0][0] = 1
    #mat[0][2] = hs[0]

    #mat[1][1] = inst[0] + hs[1]
    #mat[1][3] = hs[2]

    #mat[2][3] = hs[3]
    #mat[2][4] = hs[4]

    #mat[3][3] = inst[2] + hs[5]


    ##########

    #mat[2][1] = 2 * inst[0]

    #mat[1][0] = inst[0]
    #mat[4][2] = hs[0]

    #mat[3][2] = hs[0]

    #mat[4][2] = 1
    #mat[2][1] = 2 * inst[0]
    #mat[2][2] = hs[0]

    # # x1 = G^w1 H0^w5
    # mat[0][0] = 1
    # mat[0][4] = hs[0]

    # # x2 = G^w2 H1^w6
    # mat[1][1] = 1
    # mat[1][5] = hs[1]

    # # x3 = (G^{w1 + w2}) H2^w7
    # mat[2][2] = 1
    # mat[2][6] = hs[2]

    # # x4 = x3^(w1+w2) H3^w9
    # mat[3][3] = 1
    # mat[3][8] = hs[3]


    # # x1+x2 = G^w3 H0^w5 H0^w6      ~=     w3 = w1 + w2
    # mat[4][2] = 1
    # mat[4][4] = hs[0]
    # mat[4][5] = hs[1]

    # # 1 = x3^w3 G^{-w4} H2^{-w8}     ~= w3 = (w1+w2)^2, w8 = whatever
    # mat[5][2] = inst[2]
    # mat[5][3] = -1
    # mat[5][7] = -hs[2]

    return (Matrix(mat), vector(vec))


def M(inst):
    mat,vec = Mtheta(inst)
    return mat


def theta(inst):
    mat,vec = Mtheta(inst)
    return vec




############ (?) BC
### The following language has 4 transformations, and transformation # 2 is not generically blinding-compatible:
### It is only blinding compatible if r9: r46 + r47, where r47 is a new Ta associated variable, and r46 is Tx variable.
### @Volhovm: this is OK up to variable replacement: r46+r47 -> alpha, r47 -> beta, then r46 = alpha - beta.

# def M(inst):
#     mat = [[0 for j in range(m)] for i in range(n)]
#
#     mat[0][0] = 1         # x1 = G^w1
#     mat[1][1] = inst[0]   # x2 = x1^w1 = G^{w1 w2}
#     mat[2][2] = 1         # x1 * x2 = G^w3
#
#     return Matrix(mat)
#
# def theta(inst):
#     vec = [0 for i in range(n-nx)]
#
#     vec[0] = inst[0] + inst[1]         # x1 * x3
#
#     return vector(vec)
#
#  solution # 1:
# {Tx2_0: r8, Tx2_1: r11*r8, Tx_0_0: r9, Tx_0_1: r10, Tx_1_0: r11*r9, Tx_1_1: r10*r11, Tw2_0: r8, Tw2_1: r11, Tw2_2: (r11 + 1)*r8, Tw_0_0: -r10 + r9, Tw_0_1: 0, Tw_0_2: r10, Tw_1_0: 0, Tw_1_1: 0, Tw_1_2: 0, Tw_2_0: -r10*(r11 + 1) + (r11 + 1)*r9, Tw_2_1: 0, Tw_2_2: r10*(r11 + 1)}
#  Tw1:
# [                    -r10 + r9                             0                           r10]
# [                            0                             0                             0]
# [-r10*(r11 + 1) + (r11 + 1)*r9                             0                 r10*(r11 + 1)]
#  Tw2:
# (r8, r11, (r11 + 1)*r8)
#  Tx1:
# [     r9     r10]
# [ r11*r9 r10*r11]
#  Tx2:
# (r8, r11*r8)



######### (?) BC
# This one has a single transformation, but two distinct BC variants of that, not one unified BC variant. Why?
#    mat[0][0] = 1         # x1 = G^w1
#    mat[1][0] = inst[0]   # x2 = x1^w1 = G^{w1^2}
#    mat[2][1] = 1         # x2 = G^w2       => w2 = w1^2
#    mat[3][2] = 1         # x2 = G^w3       => w3 = w1^2

# BC (attempts)
    # Powers of 1 witness plus 2nd witness mixed in, no blinders
    #mat[0][0] = 1         # x1 = G^w1
    #mat[1][0] = inst[0]   # x2 = x1^w1 = G^{w1^2}
    #mat[2][1] = inst[1]   # x3 = x2^w2 = G^{w1^2 w2}

    # Powers of 1 witness
    #mat[0][0] = 1         # x1 = G^w1
    #mat[1][0] = inst[0]   # x2 = x1^w1 = G^{w1^2}
    #mat[2][0] = inst[1]   # x3 = x2^w1 = G^{w1^3}

    # Powers of 1 witness plus some blinders?
    #mat[0][0] = 1         # x1 = G^w1 H^w3
    #mat[0][2] = hs[0]
    #mat[1][0] = inst[0]   # x2 = x1^w1 = G^{w1^2} H^{w3 w1}
    #mat[2][1] = inst[1]   # x3 = x2^w2 H^w4 = G^{w1^2 w2} H^{w3 w1 w2 + w4}
    #mat[2][3] = hs[0]


# Tx1 * x + Tx2
# Tx1 * (x || H) + Tx2


# transformation ???
#
# x1' = x1 * G^alpha
# x2' = x2 * x1^{2 alpha} * G^{alpha^2}
# x3' = x3 *
#  (w1 + alpha)^2 w2 = w1 w2 + 2 alpha w1 w2 + alpha^2 w2


xs = [var('x_%d' % i) for i in range(nx)]
ws = [var('w_%d' % i) for i in range(m)]
x = vector(xs)
w = vector(ws)

# z variables are akin to w, but used for modelling "any witness" for blinding compatibility
zs = [var('z_%d' % i) for i in range(m)]
z = vector(zs)

assert(n == M(xs).nrows())
assert(m == M(xs).ncols())

print("M")
print(M(xs))
print("theta")
print(theta(xs))

inst_toprint = M(xs) * vector(ws)
for i in range(nx):
    print(xs[i], "=", inst_toprint[i])

print("thetas:")
for i in range(n-nx):
    print(theta(xs)[i], "=", inst_toprint[nx+i])

def find_coeff_of_var(expr, var):
    return expr.coefficient(var, 1)

def find_constant_coeff(expr):
    return expr.subs({v : 0 for v in expr.variables()})

# Matrix m as a tensor
m_tens = [[[find_coeff_of_var(M(xs)[i][j], xs[t]) for t in range(nx)] for j in range(m)] for i in range(n)]
m_tens_h = [[[find_coeff_of_var(M(xs)[i][j], hs[t]) for t in range(len(hs))] for j in range(m)] for i in range(n)]
m_tens_const = [[find_constant_coeff(M(xs)[i][j]) for j in range(m)] for i in range(n)]

#for t in range(nx):
#    print("main inst t: ", t)
#    print(Matrix([[m_tens[i][j][t] for j in range(m)] for i in range(n)]))
#
#for t in range(nh):
#    print("h t: ", t)
#    print(Matrix([[m_tens_h[i][j][t] for j in range(m)] for i in range(n)]))
#
#print("const: ")
#print(Matrix(m_tens_const))


# In[5]:


Txs = [[var('Tx_%d_%d' % (i, j)) for j in range(nx + nh + 1)] for i in range(nx)]
Tws = [[var('Tw_%d_%d' % (i,j)) for j in range(m + 1)] for i in range(m)]


#for i in range(m):
#    Tw1s[i][i] = 1

#us = [var('u0'),var('u1')]

#Tw2s[0] = var('u0') # w0 + u0
#Tw2s[1] = var('u1') # w1 + u1

#T_reduce_map = {var('U_α'): 0, var('w_α'): 0}
T_reduce_map = {}


#for i in range(nx):
#    for j in range(nx + nh + 1):
#        if i != j:
#            T_reduce_map[Txs[i][j]] = 0
#        # else:
#        #     T_reduce_map[Tx1s[i][j]] = 1
#
#for i in range(m):
#    for j in range(m + 1):
#        if i != j:
#            T_reduce_map[Tws[i][j]] = 0
#        # else:
#        #     T_reduce_map[Tw1s[i][j]] = 1



Tx = Matrix(subs_mat(Txs,T_reduce_map))
Tw = Matrix(subs_mat(Tws,T_reduce_map))

# Solution to w0 -> w0 + alpha w1 matrix
TxTw_solutions_subs = {
    Tw_0_0: 1,
    Tw_0_1: Tx_2_3,
    Tw_0_10: 0,
    Tw_0_11: 0,
    Tw_0_12: 0,
    Tw_0_13: 0,
    Tw_0_14: 0,
    #Tw_0_15: 0,
    Tw_0_15: 0,
    Tw_0_2: 0,
    Tw_0_3: 0,
    Tw_0_4: 0,
    Tw_0_5: 0,
    Tw_0_6: 0,
    Tw_0_7: 0,
    Tw_0_8: 0,
    Tw_0_9: 0,
    Tw_10_0: 0,
    Tw_10_1: 0,
    Tw_10_10: 1,
    Tw_10_11: 0,
    Tw_10_12: 0,
    Tw_10_13: 0,
    Tw_10_14: 0,
    #Tw_10_15: 0,
    Tw_10_15: 0,
    Tw_10_2: 0,
    Tw_10_3: 0,
    Tw_10_4: 0,
    Tw_10_5: 0,
    Tw_10_6: 0,
    Tw_10_7: 0,
    Tw_10_8: 0,
    Tw_10_9: 0,
    Tw_11_0: 0,
    Tw_11_1: 0,
    Tw_11_10: 0,
    Tw_11_11: 1,
    Tw_11_12: 0,
    Tw_11_13: 0,
    Tw_11_14: 0,
    #Tw_11_15: 0,
    Tw_11_15: 0,
    Tw_11_2: 0,
    Tw_11_3: 0,
    Tw_11_4: 0,
    Tw_11_5: 0,
    Tw_11_6: 0,
    Tw_11_7: 0,
    Tw_11_8: 0,
    Tw_11_9: Tx_2_3,
    Tw_12_0: 0,
    Tw_12_1: 0,
    Tw_12_10: Tx_2_3,
    Tw_12_11: 0,
    Tw_12_12: 1,
    Tw_12_13: 0,
    Tw_12_14: 0,
    #Tw_12_15: 0,
    Tw_12_15: 0,
    Tw_12_2: 0,
    Tw_12_3: 0,
    Tw_12_4: 0,
    Tw_12_5: 0,
    Tw_12_6: 0,
    Tw_12_7: 0,
    Tw_12_8: 0,
    Tw_12_9: 0,
    Tw_13_0: 0,
    Tw_13_1: 0,
    Tw_13_10: 0,
    Tw_13_11: 0,
    Tw_13_12: 0,
    Tw_13_13: 1,
    Tw_13_14: Tx_2_3,
    #Tw_13_15: 0,
    Tw_13_15: 0*0,
    Tw_13_2: 0,
    Tw_13_3: 0*Tx_2_3 + 0,
    Tw_13_4: 0,
    Tw_13_5: 0,
    Tw_13_6: 0,
    Tw_13_7: 0,
    Tw_13_8: 0,
    Tw_13_9: 0,
    Tw_14_0: 0,
    Tw_14_1: 0,
    Tw_14_10: 0,
    Tw_14_11: 0,
    Tw_14_12: 0,
    Tw_14_13: 0,
    Tw_14_14: 1,
    #Tw_14_15: 0,
    Tw_14_15: 0^2,
    Tw_14_2: 0,
    Tw_14_3: 2*0,
    Tw_14_4: 0,
    Tw_14_5: 0,
    Tw_14_6: 0,
    Tw_14_7: 0,
    Tw_14_8: 0,
    Tw_14_9: 0,
#    Tw_15_0: 0,
#    Tw_15_1: 0*Tx_2_3,
#    Tw_15_10: Tx_2_3,
#    Tw_15_11: 0,
#    Tw_15_12: 0,
#    Tw_15_13: 0,
#    Tw_15_14: 0,
#    Tw_15_15: 1,
#    Tw_15_16: 0,
#    Tw_15_17: 0,
#    Tw_15_2: 0,
#    Tw_15_3: 0,
#    Tw_15_4: 0,
#    Tw_15_5: 0,
#    Tw_15_6: 0,
#    Tw_15_7: 0,
#    Tw_15_8: 0,
#    Tw_15_9: 0,
    Tw_1_0: 0,
    Tw_1_1: 1,
    Tw_1_10: 0,
    Tw_1_11: 0,
    Tw_1_12: 0,
    Tw_1_13: 0,
    Tw_1_14: 0,
    #Tw_1_15: 0,
    Tw_1_15: 0,
    Tw_1_2: 0,
    Tw_1_3: 0,
    Tw_1_4: 0,
    Tw_1_5: 0,
    Tw_1_6: 0,
    Tw_1_7: 0,
    Tw_1_8: 0,
    Tw_1_9: 0,
    Tw_2_0: 0,
    Tw_2_1: 0,
    Tw_2_10: 0,
    Tw_2_11: 0,
    Tw_2_12: 0,
    Tw_2_13: 0,
    Tw_2_14: 0,
    #Tw_2_15: 0,
    Tw_2_15: 0,
    Tw_2_2: 1,
    Tw_2_3: Tx_2_3,
    Tw_2_4: 0,
    Tw_2_5: 0,
    Tw_2_6: 0,
    Tw_2_7: 0,
    Tw_2_8: 0,
    Tw_2_9: 0,
    Tw_3_0: 0,
    Tw_3_1: 0,
    Tw_3_10: 0,
    Tw_3_11: 0,
    Tw_3_12: 0,
    Tw_3_13: 0,
    Tw_3_14: 0,
    #Tw_3_15: 0,
    Tw_3_15: 0,
    Tw_3_2: 0,
    Tw_3_3: 1,
    Tw_3_4: 0,
    Tw_3_5: 0,
    Tw_3_6: 0,
    Tw_3_7: 0,
    Tw_3_8: 0,
    Tw_3_9: 0,
    Tw_4_0: 0,
    Tw_4_1: 0,
    Tw_4_10: 0,
    Tw_4_11: 0,
    Tw_4_12: 0,
    Tw_4_13: 0,
    Tw_4_14: 0,
    #Tw_4_15: 0,
    Tw_4_15: 0,
    Tw_4_2: 0,
    Tw_4_3: 0,
    Tw_4_4: 1,
    Tw_4_5: Tx_2_3,
    Tw_4_6: Tx_2_3^2,
    Tw_4_7: 0,
    Tw_4_8: 0,
    Tw_4_9: 0,
    Tw_5_0: 0,
    Tw_5_1: 0,
    Tw_5_10: 0,
    Tw_5_11: 0,
    Tw_5_12: 0,
    Tw_5_13: 0,
    Tw_5_14: 0,
    #Tw_5_15: 0,
    Tw_5_15: 0,
    Tw_5_2: 0,
    Tw_5_3: 0,
    Tw_5_4: 0,
    Tw_5_5: 1,
    Tw_5_6: 2*Tx_2_3,
    Tw_5_7: 0,
    Tw_5_8: 0,
    Tw_5_9: 0,
    Tw_6_0: 0,
    Tw_6_1: 0,
    Tw_6_10: 0,
    Tw_6_11: 0,
    Tw_6_12: 0,
    Tw_6_13: 0,
    Tw_6_14: 0,
    #Tw_6_15: 0,
    Tw_6_15: 0,
    Tw_6_2: 0,
    Tw_6_3: 0,
    Tw_6_4: 0,
    Tw_6_5: 0,
    Tw_6_6: 1,
    Tw_6_7: 0,
    Tw_6_8: 0,
    Tw_6_9: 0,
    Tw_7_0: 0,
    Tw_7_1: 0*Tx_2_3,
    Tw_7_10: Tx_2_3^2,
    Tw_7_3: Tx_2_3 * rr_0, # new one
    Tw_7_11: 0,
    Tw_7_12: Tx_2_3,
    Tw_7_13: 0,
    Tw_7_14: 0,
    #Tw_7_15: Tx_2_3,
    Tw_7_15: 0,
    Tw_7_2: 0,
    Tw_7_4: 0,
    Tw_7_5: 0,
    Tw_7_6: 0,
    Tw_7_7: 1,
    Tw_7_8: 0,
    Tw_7_9: 0,
    Tw_8_0: 0,
    Tw_8_1: 0,
    Tw_8_10: 0,
    Tw_8_11: 0,
    Tw_8_12: 0,
    Tw_8_13: 2*Tx_2_3,
    Tw_8_14: Tx_2_3^2,
    #Tw_8_15: 0,
    Tw_8_15: 0^2,
    Tw_8_2: 2*0,
    Tw_8_3: 2*0*Tx_2_3,
    Tw_8_4: 0,
    Tw_8_5: 0,
    Tw_8_6: 0,
    Tw_8_7: 0,
    Tw_8_8: 1,
    Tw_8_9: 0,
    Tw_9_0: 0,
    Tw_9_1: 0,
    Tw_9_10: 0,
    Tw_9_11: 0,
    Tw_9_12: 0,
    Tw_9_13: 0,
    Tw_9_14: 0,
    #Tw_9_15: 0,
    Tw_9_15: 0,
    Tw_9_2: 0,
    Tw_9_3: 0,
    Tw_9_4: 0,
    Tw_9_5: 0,
    Tw_9_6: 0,
    Tw_9_7: 0,
    Tw_9_8: 0,
    Tw_9_9: 1,
    Tx_0_0: 1,
    Tx_0_1: Tx_2_3,
    Tx_0_10: 0,
    Tx_0_11: 0,
    Tx_0_2: 0,
    Tx_0_3: 0,
    Tx_0_4: 0,
    Tx_0_5: 0,
    Tx_0_7: 0,
    Tx_0_8: 0,
    Tx_0_9: 0,
    Tx_1_0: 0,
    Tx_1_1: 1,
    Tx_1_10: 0,
    Tx_1_11: 0,
    Tx_1_2: 0,
    Tx_1_3: 0,
    Tx_1_4: 0,
    Tx_1_5: 0,
    Tx_1_7: 0,
    Tx_1_8: 0,
    Tx_1_9: 0,
    Tx_2_0: 0,
    Tx_2_1: 0,
    Tx_2_10: 0,
    Tx_2_11: 0,
    Tx_2_2: 1,
    Tx_2_4: Tx_2_3^2,
    Tx_2_5: 0,
    Tx_2_6: 0,
    Tx_2_7: 0,
    Tx_2_8: 0,
    Tx_3_0: 0,
    Tx_3_1: 0,
    Tx_3_10: 0,
    Tx_3_11: 0,
    Tx_3_2: 0,
    Tx_3_3: 1,
    Tx_3_4: 2*Tx_2_3,
    Tx_3_5: 0,
    Tx_3_6: 0,
    Tx_3_7: 0,
    Tx_3_8: 0,
    Tx_4_0: 0,
    Tx_4_1: 0,
    Tx_4_10: 0,
    Tx_4_11: 0,
    Tx_4_2: 0,
    Tx_4_3: 0,
    Tx_4_4: 1,
    Tx_4_5: 0,
    Tx_4_6: 0,
    Tx_4_7: 0,
    Tx_4_8: 0,
    Tx_5_0: 0,
    Tx_5_1: 0,
    Tx_5_10: 0,
    Tx_5_11: 0,
    Tx_5_2: 0,
    Tx_5_3: 0,
    Tx_5_4: 0,
    Tx_5_5: 1,
    Tx_5_6: 0,
    Tx_5_7: 0,
    Tx_5_8: 0,
    Tx_5_9: 0,
    Tx_0_6: 0,
    Tx_1_6: 0,
    Tx_2_9: 0,
    Tx_3_9: 0,
    Tx_4_9: 0,
    Tx_0_12: 0,
    Tx_1_12: 0,
    Tx_2_12: 0,
    Tx_3_12: 0,
    Tx_4_12: 0,
    Tx_5_12: 0,
}

#Tx = subs_mat(Tx,TxTw_solutions_subs)
#Tw = subs_mat(Tw,TxTw_solutions_subs)


#Tx = [[0 for j in range(nx+nh+1)] for i in range(nx)]
#Tw = [[0 for j in range(m+1)] for i in range(m)]
#
## x0' = x0 x1    = G^{w0+w1} H0^{w2+w3}
#Tx[0][0] = 1
#Tx[0][1] = 1
#
## x1' = x1       = G^w1 H0^w3
#Tx[1][1] = 1
#
## x2' = x2 x3 x4 = G^{(w0^2 + 2w1w0 + w1^2) + (w0 + w1)} H2^{w0+w1} H3^{w4+w5+w6}
#Tx[2][2] = 1
#Tx[2][3] = 1
#Tx[2][4] = 1
#
## x3' = x3 x4^2  = G^{2*w1(w0 + w1) + w1} H2^w1 H3^{w5 + 2 w6}
#Tx[3][3] = 1
#Tx[3][4] = 2
#
## x4' = x4       = G^{w9} H3^w6
#Tx[4][4] = 1
#
## x5' = x5       = G^{w9} H4^w1
#Tx[5][5] = 1
#
## w0'  = w0 + w1
#Tw[0][0] = 1
#Tw[0][1] = 1
#
## w1'  = w1
#Tw[1][1] = 1
#
## w2'  = w2 + w3
#Tw[2][2] = 1
#Tw[2][3] = 1
#
## w3'  = w3
#Tw[3][3] = 1
#
## w4'  = w4 + w5 + w6
#Tw[4][4] = 1
#Tw[4][5] = 1
#Tw[4][6] = 1
#
## w5'  = w5 + 2 w6
#Tw[5][5] = 1
#Tw[5][6] = 2
#
## w6'  = w6
#Tw[6][6] = 1
#
## w7'  = w7 + w12 + w15 + w10 = w0w2 + w1w2 + w0w3 + w1w3 = (w0+w1) (w2+w3)
#Tw[7][7] = 1
#Tw[7][12] = 1
#Tw[7][15] = 1
#Tw[7][10] = 1
#
## w8'  = w8 + 2 w13 + w14 = (w2 + w3)^2
#Tw[8][8] = 1
#Tw[8][13] = 2
#Tw[8][14] = 1
#
## w9'  = w9
#Tw[9][9] = 1
#
## w10' = w10
#Tw[10][10] = 1
#
## w11' = w11 + w9 = w0w1 + w1^2 = (w0+w1)w1
#Tw[11][11] = 1
#Tw[11][9] = 1
#
## w12' = w12 + w10 = w2w1 + w3w1 = (w2+w3)w1
#Tw[12][12] = 1
#Tw[12][10] = 1
#
## w13' = w13 + w14 = w2w3 + w3^2 = (w2+w3)w3
#Tw[13][13] = 1
#Tw[13][14] = 1
#
## w14' = w14
#Tw[14][14] = 1
#
## w15' = w15 + w10 = w0w3 + w1w3 = (w0+w1)w3
#Tw[15][15] = 1
#Tw[15][10] = 1
#
#
#Tx = Matrix(Tx)
#Tw = Matrix(Tw)



print("Tw and Tx")
print(Tw)
print("--------------------")
print(Tx)
print("--------------------")
#print(us)

# Backups
Txs_orig = Txs
Tws_orig = Tws

Tx_orig = Tx
Tw_orig = Tw

ts_map = {}


# In[6]:


# Optional: perform a substitution mapping for instance/witness variables
#tsmod = {t_α: 0, t_rα: 0}
tsmod = {}
x2 = vector([x[i] * (1 if x[i].subs(ts_map).subs(tsmod).full_simplify() != 0 else 0) for i in range(nx)])
w2 = vector([w[i] * (1 if w[i].subs(ts_map).subs(tsmod).full_simplify() != 0 else 0) for i in range(m)])
x2w2_map = {ws[i]:w2[i] for i in range(m)} | {xs[i]:x2[i] for i in range(len(xs))}
print(x2w2_map)
print("-------")

Tx = subs_mat(Tx,x2w2_map)
Tw = subs_mat(Tw,x2w2_map)


# Our main equation
eq_basic = stack(x2,theta(x2)) - M(x2) * w2

print("Main equation, by instance vector component 0..n:")
for i in range(n):
    print(" ", i, ": ", eq_basic[i].full_simplify())
print("-------")

# Update equation
#eq_u = Tx1 * (M(x2) * w2) + Tx2 - (M(Tx1 * x2 + Tx2) * (Tw1 * w2 + Tw2))
#x_upd_2 = Tx_top * (M(x) * w) + Tx2_top

# Temporarily disable additive components: I'm looking to see identity multiplicative matrices.
x_upd = Tx * stack(stack(x, hs), [1])
w_upd = Tw * stack(w, [1])
# x_upd = Tx1 * x
# w_upd = Tw1 * w

eq_u = stack(x_upd, theta(x_upd)) - M(x_upd) * w_upd

#eq_u = stack(Tx_top * (M(x) * w) + Tx2_top, theta(Tx_top * (M(x) * w) + Tx2_top)) - (M(Tx1 * stack(x,theta(x)) + Tx2) * (Tw1 * w + Tw2))
print("Update equation, by instance vector component 0..n:")
for (e,i) in zip(eq_u,range(n)):
    print(" ", i, ": ", e.full_simplify())


# In[7]:


# Solve for dependencies between witnesses. It seems only reasonable to AGM-like solve over the independent basis
# of trapdoors, and if w_i are dependent, we should first express them in terms of a basis.

x2_flat = [elem for elem in x2]
w2_flat = [elem for elem in w2]
hs_flat = [elem for elem in hs]
print(x2_flat + w2_flat + hs_flat)


sols = solve(list(eq_basic), hs_flat + w2_flat + x2_flat, solution_dict=True)
#sols = solve(list(eq_basic) + [w[3] + w[0] * w[2], w[0] * w[0] - 1], hs_flat + w2_flat + x2_flat, solution_dict=True)
# sols = solve(list(eq_basic) + [w2_flat[0]^2-1], x2_flat + w2_flat + hs_flat, solution_dict=True)
#sols = solve(list(eq_basic) + constraints, w2_flat + x2_flat + hs_flat, solution_dict=True)
print(sols)

# some solutions will assume e.g. hs[0] = 0, which is undesirable.
# We only want to keep solutions where hs[i] is free variable
# we only keep these solutions, and remove hs keys from it, replacing these free variables
# by hs[i] variables directly
def filter_sols_with_hs_free(sols):
    retset = []
    for sol in sols:
        if any([len(sol[hs_i].variables()) != 1 for hs_i in hs]):
            continue

        if len(set(list([sol[hs_i].variables() for hs_i in hs]))) != len(hs):
            continue

        modsol = {k: v.subs({sol[hs_i]: hs_i for hs_i in hs}) for k,v in sol.items()}
        for hs_i in hs:
            modsol.pop(hs_i)

        retset.append(modsol)

    return retset

sols = filter_sols_with_hs_free(sols)
print("filtered len: ", len(sols))
print("filtered: ", sols)
print("\n")

chosen_sol = sols[0]

# We need solutions that leave hs as fully free variables.



#!param_solution

#param_solution = { x_0: rr_0 + H0 * rr_2,
#                   x_1: rr_1 + H1 * rr_4,
#                   x_2: rr_0 * rr_1 * rr_1 + rr_1  + H2 * rr_5 * rr_5,
#                   #x_3: H0*rr_1 * rr_2 + H1*rr_1*rr_4 + rr_1^2 + H3*rr_6 + rr_1 *rr_0,
#                   #x_3: rr_0 * rr_1 + rr_1 * rr_1 + H0 * rr_2 * rr_1 + H1 * rr_4 * rr_1 + H3 * rr_6,
#                   x_3: 13*rr_1 + 25*H2*rr_5*rr_5,
#                   x_4: H3 * rr_5 + H4 * rr_10,
#                   w_0: rr_0,
#                   w_1: rr_1,
#                   w_2: rr_2,
#                   w_3: rr_0 * (-rr_2),
#                   w_4: rr_4,
#                   w_5: rr_5,
#                   w_6: rr_1 * rr_1,
#                   w_7: rr_1 * rr_4,
#                   w_8: rr_0 * rr_1 * rr_1,
#                   w_9: rr_2 * rr_1 * rr_1,
#                   w_10: rr_10,
#                   w_11: rr_5 * rr_5,
#                   w_12: rr_10 * rr_5,
#                  }
#param_values = [ {rr_0: 1}, {rr_0: -1} ]

##!param_solution
# for "knowing H allows update" lang
#param_solution = { x_0: rr_0 + H0 * rr_2,
#                   x_1: rr_1 + H0 * rr_3,
#                   x_2: rr_0 * rr_0 + rr_1 * rr_0 + rr_2 * rr_0 * H0 + rr_3 * rr_0 * H0 + H2 * rr_0 + rr_0 * rr_1 + H0 * rr_2 * rr_1,
#                   x_3: rr_1 * rr_1 + H3 * rr_1 + H0 * rr_3 * rr_1,
#                   w_0: rr_0,
#                   w_1: rr_1,
#                   w_2: rr_2,
#                   w_3: rr_3,
#                  }
#param_values = [ ]

# "w -> alpha w" is forbidden even when w is known
#param_solution = { x_0: -(-H0*rr_2 - rr_0),
#                   x_1: (H0*rr_2 + rr_0 + H1)*rr_1 + H2 * rr_3,
#                   x_2: H3 * rr_3 + H4 * rr_4,
#                   x_3: (H3 * rr_3 + H4 * rr_4 + H5)*rr_3 ,
#                   w_0: rr_0,
#                   w_1: rr_1,
#                   w_2: rr_2,
#                   w_3: rr_3,
#                   w_4: rr_4,
#                  }
#param_values = [ ]

# w0 -> w0 + w1
#param_solution = { x_0: rr_0 + H0 * rr_2,
#                   x_1: rr_1 + H0 * rr_3,
#                   x_2: rr_0 * rr_0 + rr_0 + H2 * rr_0 + H3 * rr_4,
#                   x_3: 2 * rr_0 * rr_1 + rr_1 + H2 * rr_1 + H3 * rr_5,
#                   x_4: rr_1 * rr_1 + H3 * rr_6,
#                   x_5: rr_1 * rr_1 + H4 * rr_1,
#                   w_0: rr_0,
#                   w_1: rr_1,
#                   w_2: rr_2,
#                   w_3: rr_3,
#                   w_4: rr_4,
#                   w_5: rr_5,
#                   w_6: rr_6,
#                   w_7: rr_0 * rr_2,
#                   w_8: rr_2 * rr_2,
#                   w_9: rr_1 * rr_1,
#                   w_10: rr_3 * rr_1,
#                   w_11: rr_0 * rr_1,
#                   w_12: rr_2 * rr_1,
#                   w_13: rr_2 * rr_3,
#                   w_14: rr_3 * rr_3,
#                   w_15: rr_0 * rr_3,
#                  }
#param_values = [ ]

# WHEN w0 is known: w0 -> w0 + w1
param_solution = { x_0: rr_0 + H0 * rr_2,
                   x_1: rr_1 + H0 * rr_3,
                   x_2: rr_0 * rr_0 + rr_0 + H2 * rr_0 + H3 * rr_4,
                   x_3: 2 * rr_0 * rr_1 + rr_1 + H2 * rr_1 + H3 * rr_5,
                   x_4: rr_1 * rr_1 + H3 * rr_6,
                   x_5: rr_1 * rr_1 + H4 * rr_1,
                   w_0: rr_0,
                   w_1: rr_1,
                   w_2: rr_2,
                   w_3: rr_3,
                   w_4: rr_4,
                   w_5: rr_5,
                   w_6: rr_6,
                   w_7: rr_0 * rr_2,
                   w_8: rr_2 * rr_2,
                   w_9: rr_1 * rr_1,
                   w_10: rr_3 * rr_1,
                   w_11: rr_0 * rr_1,
                   w_12: rr_2 * rr_1,
                   w_13: rr_2 * rr_3,
                   w_14: rr_3 * rr_3,
                   #w_15: rr_0 * rr_3,
                  }
param_values = [ ]



print("!param_solution: ")
print("Parameterized solution:", param_solution)
print("Parameter values:", param_values)

print("Does this solution work? main eq by instance vector component 0..n: (should be zeroes)")
for i in range(n):
    #print(" ", i, ": ", eq_basic[i].subs(param_solution).full_simplify().subs(rr_0^2 == 1).full_simplify())
    print(" ", i, ": ", eq_basic[i].subs(param_solution).full_simplify())

#if any([eq_basic[i].subs(param_solution).full_simplify().subs(rr_0^2 == 1).full_simplify() != 0 for i in range(n)]):
if any([eq_basic[i].subs(param_solution).full_simplify() != 0 for i in range(n)]):
    raise SystemExit("solution does not work")


chosen_sol = param_solution


def get_basis_from_sols(sol):
    # Assuming sols[0] is your solution dictionary
    params = set()  # find all parameters (like r4)
    for value in sol.values():
        params.update(value.variables())

    return list(params)

eq_basic_params = [x for x in get_basis_from_sols(chosen_sol) if x not in hs]
print("eq_basic_params: ", eq_basic_params)

# eq_generic_params = [rr_0, rr_1, rr_2]
# eq_constrained_params = [rr_0]

eq_u_via_params = [eq.subs(chosen_sol).full_simplify() for eq in eq_u]
#eq_u_via_params = [eq.subs(chosen_sol).full_simplify().subs(rr_0^2 == 1) for eq in eq_u]
print("eq_u: ")
for (e,i) in zip(eq_u,range(n)):
    print(" ", i, ": ", e)
print("eq_u_via_params: ", )
for (e,i) in zip(eq_u_via_params,range(n)):
    print(" ", i, ": ", e)

x_via_eq_basic_params = vector([elem.subs(chosen_sol) for elem in x2])
print(x_via_eq_basic_params)


# In[8]:


# Helper functions for solving equations AGM-style
# - Symbolic form is how equations are defined without a ring
# - "poly" or ring form is polynomials over a ring. only in this form we can extract monomials.

# Takes a ring and a list of variables, and re-assigns these variables to a ring.
# Returns:
#   - to_sym_map is a map that maps a ring variable to the original symbolic base variable
#   - ret is a list of mapped variables in a ring
def reassign_vars(R,varlists):
    ret = []
    totsum = 0
    to_sym_map = {}
    for base_vars in varlists:
        ring_vars = [R.gen(i) for i in range(totsum,totsum+len(base_vars))]
        ret.append(ring_vars)
        to_sym_map = to_sym_map | {ring_vars[i]:base_vars[i] for i in range(len(base_vars))}
        totsum += len(base_vars)
    return (to_sym_map,ret)

# Ringvars are the "Trapdoors" over which we want to extract AGM sub-equations
#ringvars = [hs, xs, ws, zs, eq_basic_params]
ringvars = [hs, xs, ws, zs, [e for e in eq_basic_params if e != rr_vars[0]]]
#ringvars = [[h for h in hs if h != hs[1]], xs, ws, zs, eq_basic_params]
print("ringvars: ", ringvars)
R = PolynomialRing(SR, concat(ringvars))
#R.inject_variables()
(to_sym_map,[poly_hs,poly_xs,poly_ws,poly_zs,poly_eq_basic_params]) = reassign_vars(R,ringvars)

print(ringvars)

# Convert a polynomial from ring form to the symbolic form
def poly_to_sym(poly):
    print(poly.subs(to_sym_map))
    return poly.subs(to_sym_map)

# Convert a polynomial from symbolic form to ring form
def sym_to_poly(poly):
    from sage.symbolic.expression_conversions import polynomial
    return polynomial(poly, ring=R)


# In[ ]:


# AGM-solve for witness/instance transformations (Tx, Tw) but NOT Ta
# *TODO* rn it's not AGM because adversary can't see the instance
# Assume the most generic form of Tw
# Model Tx as an algebraic sum of instance elements and fixed elements like H
# Take update equations, line by line, and extract sub-equations by monomial coefficients in trapdoor vars
# Trapdoor vars (secrets) are ... witness elements I think, plus DLOGs of hash-to-curve els

Tx_vars_flat = [x for sublist in Txs for x in sublist]
Tw_vars_flat = [x for sublist in Tws for x in sublist]

print(Tw_vars_flat + Tx_vars_flat)


# Transform equation to symbolic form
#eq_u_updated = [sym_to_poly(eq.subs(basic_sol)) for eq in eq_u]
eq_u_updated = [sym_to_poly(eq) for eq in eq_u_via_params]
#eq_u_updated = [sym_to_poly(eq.subs({k:basic_sol[k] for k in xs})) for eq in eq_u]
print("updated eqs: ", eq_u_updated)
print("-------")

all_monomials = list(dict.fromkeys([mon for eq in eq_u_updated for mon in eq.monomials()]))
print("all monomials: ", all_monomials)
print("-------")

coeff_eqs = [eq.monomial_coefficient(mon) for eq in eq_u_updated for mon in eq.monomials() ]
print("coeff_eqs: ", coeff_eqs)
for (e,i) in zip(coeff_eqs,range(0,len(coeff_eqs))):
    print(" ", i, ": ", e)
print("-------")

#assert(false)

def print_solutions(solutions):
    print("------------ solutions: ", solutions)
    for sol_i,sol in enumerate(solutions):
        print("============\n solution # %d:" % sol_i)
        if any([all(map(lambda x: x == 0, [Tx.subs(sol)[i][j] for j in range(nx + nh + 1)])) for i in range(nx)]):
            print("TRIVIAL SOL, INST ROW 0")

        print(sol)

        print(" Tw1:")
        print(Tw.subs(sol))


        print(" Tx1:")
        print(Tx.subs(sol))

#def iterative_solve(equations, variables):
#    # Progressive solving
#    partial_solutions = []
#    remaining_eqs = equations[:]
#
#    # Solve in batches
#    batch_size = 10
#    for i in range(0, len(equations), batch_size):
#        print("\n-------- processing next batch")
#        batch = equations[i:i+batch_size]
#        try:
#            print("trying sympy")
#            sols = solve(batch, variables, solution_dict=True, algorithm='sympy')
#        except:
#            print("fallback: trying maxima")
#            sols = solve(batch, variables, solution_dict=True, algorithm='maxima')
#
#        if sols:
#            print(sols)
#
#            combined_solutions = []
#            for s1 in partial_solutions:
#                for s2 in sols:
#                    combined = {**s1, **s2}
#                    combined_solutions.append(combined)
#
#            partial_solutions = combined_solutions
#            print_solutions(partial_solutions)
#            # Substitute known values into remaining equations
#            remaining_eqs = [eq.subs(partial_solutions) for eq in remaining_eqs[batch_size:]]
#        else:
#            print("solution was not found, whoops")
#            assert(false)
#
#    return partial_solutions


print("Does the static TxTw substitution satisfy equations?")
print(all([e == 0 for e in subs_vec(coeff_eqs,TxTw_solutions_subs)]))
print("")

print("...Solving the system of equations (takes time)...")
sols = solve(coeff_eqs, Tw_vars_flat + Tx_vars_flat, solution_dict=True, algorithm='maxima')
#sols = solve(coeff_eqs, Tw_vars_flat + Tx_vars_flat, solution_dict=True, algorithm='sympy')
#sols = solve(coeff_eqs, Tw_vars_flat + Tx_vars_flat, solution_dict=True, algorithm='fricas')
#sols = iterative_solve(coeff_eqs, Tw_vars_flat + Tx_vars_flat)


print("------------ ", len(sols)," solutions")


def is_special_case_of(sol1, sol2):
    """Check if sol1 is a special case of sol2"""
    # Create a system of equations comparing the solutions
    equations = []
    variables = set()

    for var in sol2:
        eq = sol1[var] == sol2[var]
        equations.append(eq)
        variables.update(sol2[var].variables())

    # Try to solve for the variables in sol2 that would make sol1 = sol2
    result = solve(equations, list(variables))
    return len(result) > 0  # If there's a solution, sol1 is a special case

def filter_generic_solutions(solutions):
    filtered = []
    for i, sol1 in enumerate(solutions):
        is_most_generic = True
        for j, sol2 in enumerate(solutions):
            if i != j:
                # Try substituting sol1 into sol2 to check if sol1 is more specific
                try:
                    if is_special_case_of(sol1,sol2):  # if substitution works, sol1 is less generic
                        is_most_generic = False
                        break
                except:
                    continue
        if is_most_generic:
            filtered.append(sol1)
    return filtered

print("UNFILTERED")
print_solutions(sols)

print("Filtering...")
sols_filtered = filter_generic_solutions(sols)
print("FILTERING DONE: ", len(sols_filtered), " filtered from ", len(sols), " total")
sols = sols_filtered

#TODO Test solutions for validity

print_solutions(sols)
