# ******************************************************************************************************* #
#                                                                                                         #
#  OPENREFACTORY CONFIDENTIAL                                                                             #
#  __________________                                                                                     #
#                                                                                                         #
#  Copyright (c) 2025 OpenRefactory, Inc. All Rights Reserved.                                            #
#                                                                                                         #
#  NOTICE: All information contained herein is, and remains the property of OpenRefactory, Inc. The       #
#  intellectual and technical concepts contained herein are proprietary to OpenRefactory, Inc. and        #
#  may be covered by U.S. and Foreign Patents, patents in process, and are protected by trade secret      #
#  or copyright law. Dissemination of this information or reproduction of this material is strictly       #
#  forbidden unless prior written permission is obtained from OpenRefactory, Inc.                         #
#                                                                                                         #
#  Author: Md Shoaib Shahriar Ibrahim (OpenRefactory, Inc.) - Initial Agent implementation                #
#  Contributors: Syed Tehjeebuzzaman (OpenRefactory, Inc.)                                                #
# ******************************************************************************************************* #

"""
Canonical format examples for different programming languages.
Used by both CanonicalFormatter and CodeChangeAnalyzer classes.
"""

CANONICAL_FORMAT_EXAMPLES = {
    "java": [
        {
            "input": "package com.example;\npublic class MyClass { public void doSomething(int x) { ... } }",
            "output": "com.example.MyClass#doSomething(int)",
        },
        {
            "input": "package org.demo;\npublic class User { public static String getName() { ... } }",
            "output": "org.demo.User.getName()",
        },
        {
            "input": "package com.test;\npublic class Calculator { public double add(double a, double b) { ... } }",
            "output": "com.test.Calculator#add(double, double)",
        },
        {
            "input": "package org.example;\npublic class Demo { public Demo(int x) { ... } }",
            "output": "org.example.Demo#Demo(int)"
        },
        {
            "input": "package org.example;\npublic class Demo { public Demo(String s) { ... } }",
            "output": "org.example.Demo#Demo(String)"
        },
        {
            "input": "package org.example;\npublic class Demo { public void foo(int x) { ... } }",
            "output": "org.example.Demo#foo(int)"
        },
        {
            "input": "package org.example;\npublic class Demo { public Demo(String[] s) { ... } }",
            "output": "org.example.Demo#Demo(String[])"
        },
        {
            "input": "package org.example;\npublic class Demo { public void foo(String s, long[] x) { ... } }",
            "output": "org.example.Demo#foo(String, long[])"
        },
        {
            "input": "package org.example;\npublic class Demo { public void foo(String s) { ... } }",
            "output": "org.example.Demo#foo(String)"
        },
        {
            "input": "package org.example;\npublic class Demo { public static void main(String[] args) { ... } }",
            "output": "org.example.Demo.main(String[])"
        },
        {
            "input": "package org.example;\npublic class Demo { public static int add(int[] a, int b) { ... } }",
            "output": "org.example.Demo.add(int[], int)"
        },
        {
            "input": "package org.example;\npublic class Demo { public void foo() { ... } }",
            "output": "org.example.Demo#foo()"
        },
        {
            "input": "package com.example.test;\npublic class TestJava { public List<String> processData(List<String> data) { ... } }",
            "output": "com.example.test.TestJava#processData(List)",
        },
        {
            "input": "package org.example;\npublic class Demo { public void foo(String... s) { ... } }",
            "output": "org.example.Demo#foo(String[])"
        },
        {
            "input": "package org.example;\npublic class Demo { public static void foo(String s, int... x) { ... } }",
            "output": "org.example.Demo.foo(String, int[])"
        },
        {
            "input": "package com.example;\npublic class Demo { public void foo(int[] x, MyType... m) { ... } }",
            "output": "com.example.Demo#foo(int[], MyType[])"
        },
        {
            "input": """class Example {
                        public static Runnable createRunnable() {
                            Runnable r = new Runnable() {
                                @Override
                                public void run() {
                                    System.out.println("Running");
                                }
                            };
                            return r;
                        }
                    }
                    """,
            "output": "my.pkg.Example.createRunnable()$Runnable$1#run()"

        }
    ],
    "python": [
        {"input": "def foo_bar(x, y):", "output": "module_name.foo_bar"},
        {
            "input": "class User:\n    def get_name(self): ...",
            "output": "module_name.User.get_name",
        },
        {
            "input": "class DatabaseManager:\n    def connect(self): ...",
            "output": "module_name.DatabaseManager.connect",
        },
        {
            "input": "class MathUtils:\n    @staticmethod\n    def add(a, b): ...",
            "output": "module_name.MathUtils.add",
        },
    ],
    "go": [
        {
            "input": "package mypkg\nfunc DoSomething(x int) string { ... }",
            "output": "mypkg.DoSomething(int) string",
        },
        {
            "input": "package mypkg\ntype User struct {}\nfunc (u *User) GetName() string { ... }",
            "output": "mypkg.User.GetName() string",
        },
        {
            "input": "package testgo\nfunc SimpleFunction(a, b int) int { ... }",
            "output": "testgo.SimpleFunction(int, int) int",
        },
        {
            "input": "package testgo\nfunc NewUser(id int64, name string) *User { ... }",
            "output": "testgo.NewUser(int64, string) *User",
        },
        {
            "input": "package testgo\nfunc Divide(a, b float64) (float64, error) { ... }",
            "output": "testgo.Divide(float64, float64) (float64, error)"
        },
        {
            "input": "package testgo\nfunc ValidateEmail(email string) bool { ... }",
            "output": "testgo.ValidateEmail(string) bool"
        },
    ],
    "rust": [
        {
            "input": "pub fn do_something(x: i32) -> String { ... }",
            "output": "crate::do_something(i32) -> String",
        },
        {
            "input": "impl User { pub fn get_name(&self) -> &str { ... } }",
            "output": "crate::User::get_name(&self) -> &str",
        },
        {
            "input": "struct User { id: i32, name: String }\nimpl User { pub fn validate(&self) -> bool { ... } }",
            "output": "crate::User::validate(&self) -> bool",
        },
        {
            "input": "impl Calculator { pub fn add(&self, a: f64, b: f64) -> f64 { ... } }",
            "output": "crate::Calculator::add(&self, f64, f64) -> f64",
        },
        {
            "input": "impl User { pub fn new(id: i32, name: String) -> User { ... } }",
            "output": "crate::User::new(i32, String) -> User",
        },
        {
            "input": "pub fn simple_function(a: i32, b: i32) -> i32 { ... }",
            "output": "crate::simple_function(i32, i32) -> i32",
        },
    ],
    "javascript": [
        # Regular function declaration
        {
            "input": "function regularFunction(x, y) { ... }",
            "output": "moduleName.regularFunction"
        },
        # Arrow function
        {
            "input": "const arrowFunction = (a, b) => { ... }",
            "output": "moduleName.arrowFunction"
        },
        # Function expression
        {
            "input": "const functionExpression = function(param) { ... }",
            "output": "moduleName.functionExpression"
        },
        # Class declaration
        {
            "input": "class User { constructor(id, name) { ... } }",
            "output": "moduleName.User"
        },
        # Class method
        {
            "input": "class User { getName() { ... } }",
            "output": "moduleName.User.getName"
        },
        # Static class method
        {
            "input": "class User { static validateEmail(email) { ... } }",
            "output": "moduleName.User.validateEmail"
        },
        # Object method
        {
            "input": "const API = { get: function(url) { ... } }",
            "output": "moduleName.API.get"
        },
        # Exported function
        {
            "input": "export function exportedFunction(x) { ... }",
            "output": "moduleName.exportedFunction"
        },
        # Exported arrow function
        {
            "input": "export const exportedArrow = (x) => { ... }",
            "output": "moduleName.exportedArrow"
        },
        {
            "input": "function doSomething(x) { ... }",
            "output": "moduleName.doSomething",
        },
        {
            "input": "class User { getName() { ... } }",
            "output": "moduleName.User.getName",
        },
        {
            "input": "const arrowFunction = (a, b) => { ... }",
            "output": "moduleName.arrowFunction",
        },
        {
            "input": "class Calculator { add(a, b) { ... } }",
            "output": "moduleName.Calculator.add",
        },
        {
            "input": "const IDENTIFIER = Symbol('funcName')\n /*other codes*/ ... \n [IDENTIFIER] (entry) {...}",
            "output": "moduleName.funcName",
        }
    ],
    "typescript": [
        {
            "input": "function add(a: number, b: number): number { ... }",
            "output": "moduleName.add(a: number, b: number): number",
        },
        {
            "input": "class User { getName(): string { ... } }",
            "output": "moduleName.User.getName(): string",
        },
        {
            "input": "class UserService { addUser(user: User): void { ... } }",
            "output": "moduleName.UserService.addUser(user: User): void",
        },
        {
            "input": "const calculateArea = (radius: number): number => { ... }",
            "output": "moduleName.calculateArea(radius: number): number",
        },
        {
            "input": "const arrowFunction = (a: number, b: number): number => { ... }",
            "output": "moduleName.arrowFunction(a: number, b: number): number"
        },
        {
            "input": "const functionExpression = function(param: string): string { ... }",
            "output": "moduleName.functionExpression(param: string): string"
        },
        {
            "input": "class User { static validateEmail(email: string): boolean { ... } }",
            "output": "moduleName.User.validateEmail(email: string): boolean"
        },
        {
            "input": "class UserService { getUserById(id: number): User | undefined { ... } }",
            "output": "moduleName.UserService.getUserById(id: number): User | undefined"
        },
        {
            "input": "function genericFunc<T>(arg: T): T { ... }",
            "output": "moduleName.genericFunc<T>(arg: T): T"
        },
        {
            "input": "const obj = { process: (data: string[]): void => { ... } }",
            "output": "moduleName.obj.process(data: string[]): void"
        },
        {
            "input": "export function exportedFunc(x: number): void { ... }",
            "output": "moduleName.exportedFunc(x: number): void"
        },
        {
            "input": "export const exportedArrow = (x: string): boolean => { ... }",
            "output": "moduleName.exportedArrow(x: string): boolean"
        },
    ],
    "csharp": [
        {
            "input": "namespace TestNamespace { class TestClass { public void ProcessData(System.Collections.Generic.List<System.String> data) { ... } } }",
            "output": "TestNamespace.TestClass.ProcessData(System.Collections.Generic.List<System.String>)"
        },
        {
            "input": "namespace Demo { class User { public string GetName() { ... } } }",
            "output": "Demo.User.GetName()",
        },
        {
            "input": "namespace Demo { class Math { public static int Add(int a, int b) { ... } } }",
            "output": "Demo.Math.Add(System.Int32, System.Int32)",
        },
        {
            "input": "namespace TestNamespace { class Calculator { public double Add(double a, double b) { ... } } }",
            "output": "TestNamespace.Calculator.Add(System.Double, System.Double)",
        },
        {
            "input": "namespace TestNamespace { class User { public User(int id, string name) { ... } } }",
            "output": "TestNamespace.User.User(System.Int32, System.String)",
        },
    ],
    "ruby": [
        {
            "input": "def foo_bar(x, y)\n  ...\nend",
            "output": "ModuleName.foo_bar",
        },
        {
            "input": "class User\n  def get_name\n    ...\n  end\nend",
            "output": "ModuleName::User#get_name",
        },
        {
            "input": "module TestModule\n  class User\n    def validate\n      ...\n    end\n  end\nend",
            "output": "TestModule::User#validate",
        },
        {
            "input": "module TestModule\n  def self.simple_function(x, y)\n    ...\n  end\nend",
            "output": "TestModule.simple_function",
        },
        {
            "input": "module TestModule\n  class Calculator\n    def self.get_pi\n      ...\n    end\n  end\nend",
            "output": "TestModule::Calculator.get_pi",
        },
        {
            "input": "module TestModule\n  def self.process_data(data)\n    ...\n  end\nend",
            "output": "TestModule.process_data"
        },
        {
            "input": "module TestModule\n  class User\n    def initialize(id, name)\n      ...\n    end\n  end\nend",
            "output": "TestModule::User#initialize"
        },
        {
            "input": "def fibonacci(n)\n  ...\nend",
            "output": "fibonacci"
        }
    ],
    "c": [
        {
            "input": "int do_something(int x) { ... }",
            "output": "file.c:do_something(int)",
        },
        {
            "input": "int simpleFunction(int a, int b) { ... }",
            "output": "file.c:simpleFunction(int, int)",
        },
        {
            "input": "void swapIntegers(int* a, int* b) { ... }",
            "output": "file.c:swapIntegers(int*, int*)",
        },
        {
            "input": "int validateRange(int value, int min, int max) { ... }",
            "output": "file.c:validateRange(int, int, int)",
        },
    ],
    "cpp": [
        {
            "input": "namespace testnamespace { bool validateEmail(std::string email) { ... } }",
            "output": "testnamespace::validateEmail(std::string)"
        },
        {
            "input": "namespace testnamespace { void createUser(int id, std::string name) { ... } }",
            "output": "testnamespace::createUser(int, std::string)"
        },
        {
            "input": "namespace testnamespace { class User { void setName(std::string name) { ... } }; }",
            "output": "testnamespace::User::setName(std::string)"
        },
        {
            "input": "namespace testnamespace { class User { void setName(std::string& name) { ... } }; }",
            "output": "testnamespace::User::setName(std::string)"
        },
        {
            "input": "int globalFunction(int x) { ... }",
            "output": "globalFunction(int)"
        },
        {
            "input": "namespace testnamespace { class User { void setName(std::string name) { ... } }; }",
            "output": "testnamespace::User::setName(std::string)"
        },
        {
            "input": "namespace testnamespace { class User { void setName(std::string& name) { ... } }; }",
            "output": "testnamespace::User::setName(std::string)"
        },
        {
            "input": "namespace testnamespace { int simpleFunction(int a, int b) { ... } }",
            "output": "testnamespace::simpleFunction(int, int)",
        },
        {
            "input": "namespace testnamespace { class Calculator { double add(double a, double b) { ... } }; }",
            "output": "testnamespace::Calculator::add(double, double)",
        },
        {
            "input": "namespace testnamespace { class Calculator { double add(double a, double b) { ... } }; }",
            "output": "testnamespace::Calculator::add(double, double)",
        },
    ],
    "php": [
        {
            "input": "function do_something($x) { ... }",
            "output": "\\Namespace\\do_something($x)",
        },
        {
            "input": "class User { public function getName() { ... } }",
            "output": "\\Namespace\\User::getName()",
        },
        {
            "input": "namespace TestNamespace; function simpleFunction($x, $y) { ... }",
            "output": "\\TestNamespace\\simpleFunction($x, $y)",
        },
        {
            "input": "namespace TestNamespace; class Calculator { public function add($a, $b) { ... } }",
            "output": "\\TestNamespace\\Calculator::add($a, $b)",
        },
        {
            "input": "namespace TestNamespace; class User { public function __construct($id, $name) { ... } }",
            "output": "\\TestNamespace\\User::__construct($id, $name)",
        },
    ],
}





