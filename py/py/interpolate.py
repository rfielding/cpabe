#!/usr/bin/python3

import hashlib
# Use a simple finite prime group to test this

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
    def __init__(self,T,K,cases):
        self.Cases = []
        self.K = K
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




A = G.Hp("A")
B = G.Hp("B")
C = G.Hp("C")
D = G.Hp("D")
E = G.Hp("E")

# The key that we want to target generating for this lock
# It may be for a file that already exists
T = G.Hp("TheBigSecretLock")[0]
K = G.Hp("RandomGibberJabber")

# The padlock is all public info, with all the ways it can unlock
p = Padlock(T,K,[
    ["A","B"],
    ["D"],
    ["B","C"]
])

# Us using locks, given private info in last arg
# We explicitly pick the way it opens here
userAlice = {"A":A,"B":B,"C":C}
userBob = {"D":D}
userEve = {"E":E}
print("Alice: %s" % p.Unlock(userAlice))
print("Bob: %s" % p.Unlock(userBob))
print("Eve: %s" % p.Unlock(userEve))



