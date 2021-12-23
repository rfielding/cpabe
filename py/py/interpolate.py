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
    def Hm(self,S,s):
        return G.pow(self.Hs(s),S)
    def Hpn(self,S,s,n):
        h1 = G.mul(self.Hs(s),n)
        h2 = G.Hm(S,s)
        return [h1,h2]
    def Hp(self,S,s):
        return self.Hpn(S,s,1)

# large prime.  i had to look it up
G = FiniteCyclicGroup(36497)

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
    def __init__(self,S,T,tree):
        self.Tree = tree
        K = G.Hpn(S,"K",1)
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
        # cases are of the form: [["A","B"],AB]
        for acase in self.Cases:
            satisfied = True
            for attrName in acase[0]:
                if not attrName in cert:
                    satisfied = False
            if satisfied:
                privPoints = [cert["K"]]
                for attrName in acase[0]:
                    privPoints.append(cert[attrName])
                priv = CalcKey(privPoints)
                T = acase[1][0][1]
                return UnlockPadlock2(T,privPoints)
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

# This is the same as signing
def HashCert(cert):
    pts = []
    for k in cert:
        pts.append(cert[k])
    return UnlockPadlock2(0,pts)

# Once the correct case is determined, we just need points and a diff
def UnlockPadlock2(T,pts):
    # given the diff we are off by, and points alone, we can compute lock from scratch for this case
    total = T
    n = len(pts)
    priv = CalcKey(pts)
    pub = CalcPub(pts)
    for j in range(0,n):
        total = G.add(total, G.mul(pub[j],priv[j]))
    return total

def VerifyCert(referenceCert,checkCert):
    macOfK = referenceCert["K"][1]
    for k in checkCert:
        # Given that we believe the K value of reference cert, check other cert to see if its signed by same
        pointToCheck = checkCert[k][1]
        if Verify("K",macOfK,k,pointToCheck)==False:
            return False
    return True

# Given a pair of objects, and their pre-hashed values, to verify that they were signed by same signer.
# Use a signed value that you already trust for this.
def Verify(a,Ma,b,Mb):
    # Given: a,b,Ma = H(a)^S1, Mb = H(b)^S2
    # Trying to detect S1 != S2
    #
    # H(a)^S1 H(a)^n H(b)^S2 H(b)^n
    # H(a)^{S1+n} H(b)^{S2+n}
    # Ma^n Mb^n
    # =
    # H(a)^S1 H(b)^S2 H(a)^n H(b)^n
    # Ma Mb (H(a)H(b))^n
    n = 100
    Ha = G.Hs(a)
    Han = G.pow(Ha,n)
    Hb = G.Hs(b)
    Hbn = G.pow(Hb,n)
    expected = G.mul(G.mul(Ma,Han),G.mul(Mb,Hbn))
    got = G.mul(G.mul(Ma,Mb),G.pow(G.mul(Ha,Hb),n))
    return G.sub(expected,got)==0


# A certificate is an ordinary map of attribute assertions, with signed points for the assertions.
# a hash of these attributes is just passing a curve through the points, just like key derivation
def Issue(S,attrs):
    # Bind all of these attributes together with a nonce
    # TODO: ratio attack:w!
    nonce = G.Hm(S,attrs["id"])
    attrs["K"] = G.Hpn(S,"K",nonce)
    # treat attr:val with ? as a request to sign an assertion
    attrs["id:%s" % attrs["id"]] = "?"
    del attrs["id"]
    attrs["exp"] = round(time())
    attrs["exp:%s" % attrs["exp"]] = "?"
    del attrs["exp"]
    for a in attrs:
        semi = a.find(":")
        if semi > 0:
            k = a[0:semi]
            v = a[semi+1:]
            g = G.Hp(S,a)
            attrs[a] = [G.mul(nonce,g[0]), g[1]]
    return attrs
         
# The CA secret....
CASecret = G.Hs("F!@rkingDifficult!123")
CAPub = G.Hs("PublicKey")

# Deterministic "random" key
TargetKey = G.Hs("f1rstP@dlock")

p = Padlock(CASecret,TargetKey,[ 
  "and", 
  ["or","cit:NL","cit:US"], 
  "age:adult" 
])

userAlice = Issue(CASecret,{
  "id": "alice@gmail.com", 
  "cit:US": "?",
  "age:drive": "?",
  "age:adult": "?"
})
userBob = Issue(CASecret,{
  "id": "bob@gmail.com", 
  "cit:US": "?"
})
userEve = Issue(CASecret,{
  "id": "eve@yahoo.com", 
  "cit:NL": "?",
  "age:drive": "?",
  "age:adult": "?"
})

print("Padlock Condition to unlock key %d: %s" % (TargetKey,p.Tree))
print()

print("Unlocking locks is public:")
print("  Alice: %s" % p.Unlock(userAlice))
print("  Bob: %s" % p.Unlock(userBob))
print("  Eve: %s" % p.Unlock(userEve))
print()

print("Notice that signed points are different for Alice and Eve")
print("  Alice (%d): %s" % (HashCert(userAlice),userAlice))
print("  Eve( (%d): %s" % (HashCert(userEve),userEve))

print()
print("The public (commutative) hash for a cert subset is just passing through all points")
answer = Verify(
        #"id:alice@gmail.com",userAlice["id:alice@gmail.com"][1],
        "K",userAlice["K"][1],
        "K",userBob["id:bob@gmail.com"][1],
)
print("Check that Alice has a valid cert, given that Bob does: %s" % VerifyCert(userAlice,userBob))
userBob["id:bobg@gmail.com"]=[334,432]
print("Check that Alice detects modified Bob cert fails: %s" % (False==VerifyCert(userAlice,userBob)))
