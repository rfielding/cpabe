#!/usr/bin/python3

from time import time
import hashlib





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
        return int.from_bytes(hashlib.sha256(s.encode()).digest(),'big') % self.N
    def Hpn(self,S,n,s):
        h1 = G.mul(n,self.Hs((s+"X"+("%s" % S))))
        h2 = self.Hs((s+"Y"+("%s" % S)))
        return [h1,h2]
    def Hp(self,S,s):
        return self.Hpn(S,1,s)

G = FiniteCyclicGroup(7919)

def CalcKey(pts):
    n = len(pts)
    priv = []
    # equiv to:
    #  ((Y_j)(X_j))(X_j)^{n-2}
    # =((Y_j)(X_j)^{n-1}v^{n-1}
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
    # equiv to:
    #  X_z = v x_z
    #  den = \prod_i v(x_j-x_i)
    #  den = v^{n-1} \prod_i (x_j-x_i)
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
    def __init__(self,S,T,K,tree):
        self.K = K
        # compile the tree to CNF and convert it to cases
        cnft = cnfTree(tree)
        cases = []
        for andCase in cnft[1:]:
            rowhdr = []	
            for term in andCase[1:]:
                rowhdr.append(term)
            cases.append(rowhdr)
        self.Cases = []
        for attrs in cases:
            pts = [K]
            for a in attrs:
                pts.append(G.Hp(S,a))
            self.Cases.append([
                attrs,
                CreatePadlockCase(T,pts)
            ])
    def Unlock(self,cert):
        # a multiplier for x axis of points to enforce consistent user attrs
        pk = cert["pk"]
        # cases are of the form: [["A","B"],AB]
        for acase in self.Cases:
            satisfied = True
            for attrName in acase[0]:
                if not attrName in cert:
                    satisfied = False
            if satisfied:
                k = self.K
                privPoints = [[G.mul(1,k[0]),k[1]]]
                for attrName in acase[0]:
                    p = cert[attrName]
                    privPoints.append([G.mul(pk,p[0]),p[1]])
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

def Issue(S,attrs):
    # TODO: an actual JWT with a signature, and a public key so that it can be challenged
    pk = G.Hp(S,attrs["id"])[0]
    attrs["pk"] = pk
    attrs["id:%s" % attrs["id"]] = "?"
    attrs["exp"] = round(time())
    for a in attrs:
        semi = a.find(":")
        if semi > 0:
            k = a[0:semi]
            v = a[semi+1:]
            g = G.Hp(S,a)
            attrs[a] = [G.mul(G.inv(pk),g[0]), g[1]]
    return attrs
         
# Some certificates issued by CA
CASecret = 432

# Yes, we actually compile arbitrary and/or exprs to CNF for you
p = Padlock(CASecret,899,[9012,134],[ 
  "and", 
  ["or","cit:NL","cit:US"], 
  "age:adult" 
])
userAlice = Issue(CASecret,{
  "id": "Alice", 
  "cit:US": "?",
  "age:drive": "?",
  "age:adult": "?"
})
userBob = Issue(CASecret,{
  "id": "Bob", 
  "cit:US": "?"
})
userEve = Issue(CASecret,{
  "id": "Eve", 
  "cit:NL": "?",
  "age:drive": "?",
  "age:adult": "?"
})

# Unlocking locks is public
print("Alice: %s" % p.Unlock(userAlice))
print("Bob: %s" % p.Unlock(userBob))
print("Eve: %s" % p.Unlock(userEve))


