nx = 1            # number of instance elements
ntheta = 1        # number of theta elems
n = nx + ntheta   # number of equations
m = 2             # number of witness elements
nh = 1            # number of random bases

hs = [var('H%d' % i) for i in range(nh)]
rr_vars = [var('rr_%d' % i) for i in range(m)]


print(hs)

print(rr_vars)

def Mtheta(inst):
    mat = [[0 for j in range(m)] for i in range(n)]
    vec = [0 for i in range(n - nx)]

    # x0 = G^w0 * H^w1
    mat[0][0] = 1
    mat[0][1] = hs[0]

    # theta[0] = G^w0
    mat[1][0] = 1

    # we force w0 to be 5
    vec[0] = 5

    return (Matrix(mat), vector(vec))

# sage variables for statement and wittness
xs = [var('x_%d' % i) for i in range(nx)]
ws = [var('w_%d' % i) for i in range(m)]
x = vector(xs)
w = vector(ws)


def M(inst):
    mat,vec = Mtheta(inst)
    return mat

def theta(inst):
    mat,vec = Mtheta(inst)
    return vec

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


Txs = [[var('Tx_%d_%d' % (i, j)) for j in range(nx + nh + 1)] for i in range(nx)]
Tws = [[var('Tw_%d_%d' % (i,j)) for j in range(m + 1)] for i in range(m)]

Tx = Matrix(Txs)
Tw = Matrix(Tws)

print("Tw and Tx")
print(Tw)
print("--------------------")
print(Tx)
print("--------------------")

def stack(vec1,vec2):
    return vector(list(vec1) + list(vec2))

# eq_basic = stack(x2,theta(x2)) - M(x2) * w2

eq_basic = stack(x,theta(x)) - M(x) * w

print("Main equation, by instance vector component 0..n:")
for i in range(n):
    print(" ", i, ": ", eq_basic[i])
    #print(" ", i, ": ", eq_basic[i].full_simplify())
print("-------")

print("xstack")
print(stack(stack(x, hs), [1]))
print(f"{stack(w, [1]) = }")

x_upd = Tx * stack(stack(x, hs), [1])
w_upd = Tw * stack(w, [1])

print(f"{x_upd=}")

eq_u = stack(x_upd, theta(x_upd)) - M(x_upd) * w_upd

print("Update equation, by instance vector component 0..n:")
for (e,i) in zip(eq_u,range(n)):
    print(" ", i, ": ", e)
    #print(" ", i, ": ", e.full_simplify())


param_solution = { x_0: 5 + H0 * rr_1,
                  w_0: 5,
                  w_1: rr_1,
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
else:
    print("Yes! Solution works")


chosen_sol = param_solution

def get_basis_from_sols(sol):
    # Assuming sols[0] is your solution dictionary
    params = set()  # find all parameters (like r4)
    for value in sol.values():
        if hasattr(value, "variables"):
            params.update(value.variables())

    return list(params)

eq_basic_params = [x for x in get_basis_from_sols(chosen_sol) if x not in hs]
print("eq_basic_params: ", eq_basic_params)

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

ringvars = [hs, eq_basic_params] # [e for e in eq_basic_params if e != rr_vars[0]]]


import itertools

def concat(lists):
    return list(itertools.chain.from_iterable(lists))

print("ringvars: ", ringvars)
R = PolynomialRing(SR, concat(ringvars))

print(f"{R=}")
#R.inject_variables()
(to_sym_map,[poly_hs,poly_eq_basic_params]) = reassign_vars(R,ringvars)

print(ringvars)

# Convert a polynomial from symbolic form to ring form
def sym_to_poly(poly):
    from sage.symbolic.expression_conversions import polynomial
    return polynomial(poly, ring=R)


Tx_vars_flat = [x for sublist in Txs for x in sublist]
Tw_vars_flat = [x for sublist in Tws for x in sublist]

print(Tw_vars_flat + Tx_vars_flat)

eq_u_via_params = [eq.subs(chosen_sol).full_simplify() for eq in eq_u]
#eq_u_via_params = [eq.subs(chosen_sol).full_simplify().subs(rr_0^2 == 1) for eq in eq_u]
print("eq_u: ")
for (e,i) in zip(eq_u,range(n)):
    print(" ", i, ": ", e)
print("eq_u_via_params: ", )
for (e,i) in zip(eq_u_via_params,range(n)):
    print(" ", i, ": ", e)


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

sol_vars = Tw_vars_flat + Tx_vars_flat

print("...Solving the system of equations (takes time)...")

sols = solve(coeff_eqs, sol_vars, solution_dict=True, algorithm='sympy')

print_solutions(sols)
