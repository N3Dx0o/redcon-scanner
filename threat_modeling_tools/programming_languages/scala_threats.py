from typing import Annotated


async def scala_general_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Scala function does, its purpose, and its role in the application. Should include Scala-specific operations, JVM usage, functional programming patterns, and any Scala-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the Scala function including all statements, variable assignments, control flow, function calls, Scala operations, and any nested logic. This is the actual Scala code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'src/main/scala/UserService.scala', 'lib/security/CryptoUtils.scala', 'app/network/HttpHandler.scala'). Used for context and reporting."], 
    scala_context: Annotated[str, "Additional Scala context including the Scala version (e.g., Scala 2.13, 3.x), JVM version, build tool (sbt, Maven, Gradle), and critical Scala operations this function handles."],
    list_of_scala_threats: Annotated[list[str], "A comprehensive list of Scala-specific threats and vulnerabilities to check for during analysis. Each item should be a specific Scala threat type (e.g., 'Scala Deserialization Vulnerabilities', 'Scala Reflection Vulnerabilities', 'Scala Macro Vulnerabilities', 'Scala Implicit Vulnerabilities', 'Scala Type System Vulnerabilities', 'Scala Pattern Matching Vulnerabilities', 'Scala Case Class Vulnerabilities', 'Scala Trait Vulnerabilities', 'Scala Object Vulnerabilities', 'Scala Companion Object Vulnerabilities', 'Scala Package Object Vulnerabilities', 'Scala Sealed Class Vulnerabilities', 'Scala Abstract Class Vulnerabilities', 'Scala Generic Vulnerabilities', 'Scala Variance Vulnerabilities', 'Scala Covariance Vulnerabilities', 'Scala Contravariance Vulnerabilities', 'Scala Invariance Vulnerabilities', 'Scala Higher-Kinded Types Vulnerabilities', 'Scala Type Lambda Vulnerabilities', 'Scala Path-Dependent Types Vulnerabilities', 'Scala Structural Types Vulnerabilities', 'Scala Existential Types Vulnerabilities', 'Scala Singleton Types Vulnerabilities', 'Scala Refined Types Vulnerabilities', 'Scala Phantom Types Vulnerabilities', 'Scala Dependent Types Vulnerabilities', 'Scala GADT Vulnerabilities', 'Scala F-Bounded Polymorphism Vulnerabilities', 'Scala Self Types Vulnerabilities', 'Scala Cake Pattern Vulnerabilities', 'Scala Dependency Injection Vulnerabilities', 'Scala Akka Vulnerabilities', 'Scala Actor Vulnerabilities', 'Scala Actor System Vulnerabilities', 'Scala Message Passing Vulnerabilities', 'Scala Supervision Vulnerabilities', 'Scala Circuit Breaker Vulnerabilities', 'Scala Stream Vulnerabilities', 'Scala Future Vulnerabilities', 'Scala Promise Vulnerabilities', 'Scala Execution Context Vulnerabilities', 'Scala Thread Pool Vulnerabilities', 'Scala Async Vulnerabilities', 'Scala Await Vulnerabilities', 'Scala Blocking Vulnerabilities', 'Scala Non-Blocking Vulnerabilities', 'Scala Reactive Streams Vulnerabilities', 'Scala Play Framework Vulnerabilities', 'Scala Spark Vulnerabilities', 'Scala Kafka Vulnerabilities', 'Scala ZIO Vulnerabilities', 'Scala Cats Vulnerabilities', 'Scala Scalaz Vulnerabilities', 'Scala Monad Vulnerabilities', 'Scala Functor Vulnerabilities', 'Scala Applicative Vulnerabilities', 'Scala Monad Transformer Vulnerabilities', 'Scala Free Monad Vulnerabilities', 'Scala Tagless Final Vulnerabilities', 'Scala Effect System Vulnerabilities', 'Scala Resource Management Vulnerabilities', 'Scala Bracket Vulnerabilities', 'Scala Scope Vulnerabilities', 'Scala Region Vulnerabilities', 'Scala Managed Vulnerabilities', 'Scala Auto-Closeable Vulnerabilities', 'Scala Try Vulnerabilities', 'Scala Either Vulnerabilities', 'Scala Option Vulnerabilities', 'Scala Validation Vulnerabilities', 'Scala IO Vulnerabilities', 'Scala File Vulnerabilities', 'Scala Network Vulnerabilities', 'Scala Database Vulnerabilities', 'Scala SQL Vulnerabilities', 'Scala NoSQL Vulnerabilities', 'Scala Cache Vulnerabilities', 'Scala Session Vulnerabilities', 'Scala Cookie Vulnerabilities', 'Scala CSRF Vulnerabilities', 'Scala XSS Vulnerabilities', 'Scala SQL Injection Vulnerabilities', 'Scala Command Injection Vulnerabilities', 'Scala Path Traversal Vulnerabilities', 'Scala File Upload Vulnerabilities', 'Scala XXE Vulnerabilities', 'Scala XML Vulnerabilities', 'Scala JSON Vulnerabilities', 'Scala YAML Vulnerabilities', 'Scala Serialization Vulnerabilities', 'Scala Deserialization Vulnerabilities', 'Scala Pickle Vulnerabilities', 'Scala Kryo Vulnerabilities', 'Scala Jackson Vulnerabilities', 'Scala Circe Vulnerabilities', 'Scala Play JSON Vulnerabilities', 'Scala Spray JSON Vulnerabilities', 'Scala Argonaut Vulnerabilities', 'Scala uPickle Vulnerabilities', 'Scala Boopickle Vulnerabilities', 'Scala Chill Vulnerabilities', 'Scala Chill Vulnerabilities', 'Scala Chill Vulnerabilities', etc.)."] = None
) -> str:
    """
    Analyze a Scala function for Scala-specific security vulnerabilities and threats.
    
    This function focuses specifically on Scala vulnerabilities, Scala implementation flaws,
    and Scala-specific attack vectors that could lead to deserialization attacks,
    reflection abuse, macro exploitation, or exploitation of Scala functionality.
    
    Args:
        function_explanation: Human-readable description of the Scala function's purpose and behavior
        function_body: Complete source code of the Scala function to be analyzed
        file_path: Full path to the file containing the Scala function for context
        scala_context: Additional Scala context and Scala implementation information
        list_of_scala_threats: List of specific Scala threats to evaluate
        
    Returns:
        str: Detailed Scala analysis report including identified vulnerabilities,
             Scala-specific attack vector analysis, potential Scala impact, and remediation
             recommendations specific to Scala security.
             
    Example:
        result = await scala_general_threats(
            function_explanation="User authentication service with Akka actors and case classes",
            function_body="case class User(id: String, name: String)\nclass AuthActor extends Actor { ... }",
            file_path="src/main/scala/UserService.scala",
            scala_context="Scala 3.x with Akka actors and Play Framework",
            list_of_scala_threats=["Scala Deserialization Vulnerabilities", "Scala Akka Vulnerabilities", "Scala Case Class Vulnerabilities", "Scala Actor Vulnerabilities"]
        )
        
    Note:
        This function should be used for analyzing Scala functions, Scala implementations,
        and Scala-specific code where vulnerabilities could lead to Scala compromise
        or Scala functionality exploitation. Focus on Scala security best practices.
    """
    msg = f"""
SCALA GENERAL THREAT ANALYSIS REQUEST

Function Context:
- Scala Purpose: {function_explanation}
- File Location: {file_path}
- Scala Context: {scala_context}
- Scala Threats to Evaluate: {', '.join(list_of_scala_threats or ['General security threats, Common vulnerabilities, OWASP Top 10'])}

Scala Source Code to Analyze:
{function_body}

Please perform a comprehensive Scala security analysis focusing on the specified threats and provide detailed findings with Scala-specific attack vector analysis, potential Scala impact, and remediation guidance specific to Scala vulnerabilities and secure Scala development practices.
"""

    return msg
