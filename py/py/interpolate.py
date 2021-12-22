#!/usr/bin/python3

import hashlib
# Use a simple finite prime group to test this





# Convert a tree into or over and, prefix notation.
def cnfTree(t):
	if isinstance(t,list):
		# evaluate our args first
		args = []
		for n in range(1,len(t)):
			args.append( cnfTree(t[n]) )
		# sort: terms before and before or
		argsSorted = []
		for a in args:
			if not isinstance(a,list):
				argsSorted.append(a)
		for a in args:
			if isinstance(a,list) and a[0]=="and":
				argsSorted.append(a)
		for a in args:
			if isinstance(a,list) and a[0]=="or":
				argsSorted.append(a)
		r = []
		r.append(t[0])
		# merge and and or
		aPrev = None
		for a in argsSorted:
			if t[0]=="or" and isinstance(a,list) and a[0]=="or":
				for m in range(1,len(a)):
					r.append(a[m])
			elif t[0]=="and" and isinstance(a,list) and a[0]=="and":
				for m in range(1,len(a)):
					r.append(a[m])
			elif aPrev and aPrev[0]=="and" and isinstance(a,list) and a[0]=="and":
				for m in range(1,len(a)):
					aPrev.append(a[m])
			elif aPrev and aPrev[0]=="or" and isinstance(a,list) and a[0]=="or":
				for m in range(1,len(a)):
					aPrev.append(a[m])
			else:
				r.append(a)
			aPrev = a
		# now we distribute and over or
		if isinstance(aPrev,list) and aPrev[0]=="or" and t[0]=="and":
			# create an argsD to or with the last arg, which should be the only or left
			argsD = []
			for a in r[1:-1]:
				argsD.append(a)
			r2 = ["or"]
			for m in range(1,len(aPrev)):
				v = ["and"]
				for d in argsD:
					v.append(d)
				v.append(aPrev[m])
				r2.append(v)
			return r2	
		else:	
			return r
	else:
		return t



class FiniteCyclicGroup:
    def __init__(self,n):
        self.N = n
    def add(self,a,b):
        return (a + b) % self.N
    def sub(self,a,b):
        return (a - b) % self.N
    def mul(self,a,b):
        return (a * b) % self.N
    def inv(self,a):
        return (a ** (self.N-2)) % self.N
    def pow(self,a,b):
        return (a ** b) % self.N
    def Hs(self,s):
        return int.from_bytes(hashlib.sha256(s).digest(),'big') % self.N
    def Hp(self,s):
        h1 = self.Hs((s+"X").encode())
        h2 = self.Hs((s+"Y").encode())
        return [h1,h2]

G = FiniteCyclicGroup(7919)

def CalcKey(pts):
    n = len(pts)
    priv = []
    # equiv to:
    # - (Y_j)(X_j)^{n-1}
    for j in range(0,n):
        X_j = pts[j][0]
        Y_j = pts[j][1]
        num = 1
        for i in range(0,n):
            if i == j:
                num = G.mul(num,Y_j)
            else:
                num = G.mul(num,X_j)
        priv.append(num)
    return priv

def CalcPub(pts):
    n = len(pts)
    pub = []
    for j in range(0,n):
        X_j = pts[j][0]
        den = 1
        for i in range(0,n):
            if i == j:
                pass
            else:
                X_i = pts[i][0]
                den = G.mul(den,G.sub(X_j,X_i))
        # division may be a privileged operation
        pub.append(G.inv(den))
    return pub

# The CA issues padlocks.  The end result should
# be safe to publish, so should contain no secrets
class Padlock:
    # Gives a list of all the ways that the lock is satisfied
    def __init__(self,T,K,tree):
        self.K = K
        # compile the tree to CNF and convert it to cases
        cnft = cnfTree(tree)
        cases = []
        for andCase in cnft[1:]:
            rowhdr = []	
            for term in andCase[1:]:
                rowhdr.append(term)
            cases.append(rowhdr)
        print("%s" % cases)
        self.Cases = []
        for attrs in cases:
            pts = [K]
            for a in attrs:
                pts.append(G.Hp(a))
            self.Cases.append([
                attrs,
                CreatePadlockCase(T,pts)
            ])
    def Unlock(self,cert):
        # cases are of the form: [["A","B"],AB]
        for acase in self.Cases:
            satisfied = True
            for attrName in acase[0]:
                if not attrName in cert:
                    satisfied = False
            if satisfied:
                privPoints = [self.K]
                for attrName in acase[0]:
                    privPoints.append(cert[attrName])
                priv = CalcKey(privPoints)
                return UnlockPadlock(acase[1],priv)
        return 0

# Perform a pre-calculation to avoid non-linear
# operations, and to avoid giving away the means to form identities
def CreatePadlockCase(T,pts):
    n = len(pts)
    priv = CalcKey(pts)
    pub = CalcPub(pts)
    total = 0
    for j in range(0,n):
        total = G.add(total, G.mul(pub[j],priv[j]))
    return [[pub,G.sub(T,total)]]


def UnlockPadlock(v,priv):
    pub = v[0][0]
    n = len(pub)
    pubK = v[0][1]
    total = pubK
    # in EC pairs, this would be a product of pre-paired objecs:
    #   \prod_j^{K,A,B} e( G1, priv_j G2)^{pub[j]}
    for j in range(0,n):
        total = G.add(total, G.mul(pub[j],priv[j]))
    return total


# Some attributes that we want to decrypt to
aUK = G.Hp("cit:UK")
aUS = G.Hp("cit:US")
aNL = G.Hp("cit:NL")
aAD = G.Hp("age:adult")
aDR = G.Hp("age:drive")

# The target key may be an existing key for a file
# K acts as a nonce for the curves
T = G.Hp("TheBigSecretLock")[0]
K = G.Hp("RandomGibberJabber")

# Yes, we actually compile arbitrary and/or exprs to CNF for you
p = Padlock(G.Hp("oldExistingKey")[0],G.Hp("2022-12-31:01:03:32"),[ 
  "and", 
  ["or","cit:NL","cit:US"], 
  "age:adult" 
])

userAlice = { "cit:US":aUS, "age:drive": aDR, "age:adult": aAD }
userBob = {"cit":aUS}
userEve = {"cit:NL":aNL, "E":aDR}

print("Alice: %s" % p.Unlock(userAlice))
print("Bob: %s" % p.Unlock(userBob))
print("Eve: %s" % p.Unlock(userEve))


