Run from under IntelJ IDEA.

Or set the CLASSPATH variable to point to all the jars in the dependencies and run
`java -classpath $CLASSPATH TestVectorChecker`

Note: A sample Maven `pom.xml` file with the required dependencies exists under the `/target` folder. 

`java -version` outputs
java version "1.8.0_181"
Java(TM) SE Runtime Environment (build 1.8.0_181-b13)
Java HotSpot(TM) 64-Bit Server VM (build 25.181-b13, mixed mode)

Output:

--- i2p OUTPUT ---
0: false
1: true
2: false
3: true
4: false
5: true
6: false
7: true
8: false
9: true
10: true
11: false
12: false
13: true
14: false

--- BC OUTPUT ---
0: false
1: true
2: false
3: true
4: false
5: true
6: false
7: true
8: false
9: false
10: false
11: false
12: false
13: true
14: false