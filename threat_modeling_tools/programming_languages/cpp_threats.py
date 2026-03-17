from typing import Annotated


async def cpp_general_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the C++ function does, its purpose, and its role in the application. Should include business logic context, memory management considerations, and any security-relevant behaviors specific to C++ applications."],
    function_body: Annotated[str, "The complete C++ source code of the function including all statements, variable assignments, control flow, function calls, memory operations, and any nested logic. This is the actual C++ code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'src/controllers/UserController.cpp', 'app/services/AuthService.cpp', 'lib/utils/validation.cpp'). Used for context and reporting."], 
    list_of_cpp_threats: Annotated[list[str], "A comprehensive list of general C++ security threats and vulnerabilities to check for during analysis. Each item should be a specific C++ threat type (e.g., 'Buffer Overflow', 'Buffer Underflow', 'Stack Overflow', 'Heap Overflow', 'Use-After-Free', 'Double-Free', 'Memory Leaks', 'Dangling Pointers', 'Null Pointer Dereference', 'Integer Overflow', 'Integer Underflow', 'Type Confusion', 'Format String Vulnerabilities', 'Integer Conversion Issues', 'Array Bounds Violations', 'Uninitialized Variables', 'Race Conditions', 'Thread Safety Issues', 'Exception Safety Violations', 'Resource Leaks', 'Input Validation Flaws', 'Command Injection', 'Path Traversal', 'Deserialization Vulnerabilities', 'Cryptographic Implementation Bugs', etc.)."] = None
) -> str:
    """
    Analyze a C++ function for general security vulnerabilities and potential threats.
    
    This function serves as the primary entry point for C++ threat modeling analysis.
    It takes a C++ function's metadata and source code, along with a list of C++-specific threats
    to check for, and returns a comprehensive security analysis focused on C++ application security.
    
    Args:
        function_explanation: Human-readable description of the C++ function's purpose and behavior
        function_body: Complete C++ source code of the function to be analyzed
        file_path: Full path to the C++ file containing the function for context
        list_of_cpp_threats: List of specific C++ security threats to evaluate
        
    Returns:
        str: Detailed analysis report including identified vulnerabilities, 
             severity assessments, impact analysis, and remediation recommendations
             specific to C++ application security.
             
    Example:
        result = await cpp_general_threats(
            function_explanation="User authentication function that validates credentials and creates session tokens",
            function_body="bool authenticateUser(const std::string& username, const std::string& password) { ... }",
            file_path="src/auth/AuthService.cpp",
            list_of_cpp_threats=["Buffer Overflow", "Integer Overflow", "Input Validation Flaws", "Memory Leaks"]
        )
        
    Note:
        This function should be used as part of a comprehensive C++ security review process.
        The analysis quality depends on the completeness of the C++ threat list and
        the accuracy of the function explanation provided.
    """
    msg = f"""
C++ GENERAL THREAT ANALYSIS REQUEST

Function Context:
- C++ Purpose: {function_explanation}
- File Location: {file_path}
- C++ Threats to Evaluate: {', '.join(list_of_cpp_threats or ['General security threats, Common vulnerabilities, OWASP Top 10'])}

C++ Source Code to Analyze:
{function_body}

Please perform a comprehensive C++ security analysis focusing on the specified threats and provide detailed findings with severity ratings and remediation guidance specific to C++ security best practices.
"""

    return msg


async def cpp_memory_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the C++ memory function does, its purpose in memory management, and its role in handling dynamic memory operations. Should include memory allocation, deallocation, pointer operations, and any memory-related security behaviors."],
    function_body: Annotated[str, "The complete C++ source code of the memory function including all statements, variable assignments, control flow, memory operations, pointer manipulations, and any nested logic. This is the actual C++ memory code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'src/memory/MemoryManager.cpp', 'lib/utils/BufferUtils.cpp', 'app/data/DataProcessor.cpp'). Used for context and reporting."], 
    memory_context: Annotated[str, "Additional C++ memory context including the memory management approach (e.g., manual allocation, smart pointers, RAII), memory patterns used (e.g., stack allocation, heap allocation, custom allocators), and critical memory operations this function handles."],
    list_of_memory_threats: Annotated[list[str], "A comprehensive list of C++ memory-specific threats and vulnerabilities to check for during analysis. Each item should be a specific memory threat type (e.g., 'Buffer Overflow', 'Buffer Underflow', 'Stack Overflow', 'Heap Overflow', 'Use-After-Free', 'Double-Free', 'Memory Leaks', 'Dangling Pointers', 'Null Pointer Dereference', 'Wild Pointers', 'Stale Pointers', 'Memory Corruption', 'Heap Spraying', 'Stack Smashing', 'Return Address Overwrite', 'Function Pointer Overwrite', 'Virtual Table Corruption', 'Memory Exhaustion', 'Fragmentation Attacks', 'Uninitialized Memory Access', 'Memory Disclosure', 'ASLR Bypass', 'DEP Bypass', 'ROP Chain Construction', 'JOP Attacks', 'COOP Attacks', etc.)."] = None
) -> str:
    """
    Analyze a C++ function for memory safety vulnerabilities and threats in memory management operations.
    
    This function focuses specifically on C++ memory vulnerabilities, memory management flaws,
    and memory-specific attack vectors that could lead to memory corruption, code execution,
    or exploitation of memory management functionality.
    
    Args:
        function_explanation: Human-readable description of the C++ function's memory management purpose and behavior
        function_body: Complete C++ source code of the memory function to be analyzed
        file_path: Full path to the C++ file containing the memory function for context
        memory_context: Additional C++ memory context and memory management approach information
        list_of_memory_threats: List of specific C++ memory threats to evaluate
        
    Returns:
        str: Detailed C++ memory analysis report including identified vulnerabilities,
             memory-specific attack vector analysis, potential memory impact, and remediation
             recommendations specific to C++ memory security.
             
    Example:
        result = await cpp_memory_threats(
            function_explanation="Dynamic buffer allocation and management for user input processing",
            function_body="char* allocateBuffer(size_t size) { return new char[size]; }",
            file_path="src/memory/BufferManager.cpp",
            memory_context="Manual memory management with new/delete operators and custom buffer handling",
            list_of_memory_threats=["Buffer Overflow", "Memory Leaks", "Use-After-Free", "Double-Free"]
        )
        
    Note:
        This function should be used for analyzing C++ memory management functions, pointer operations,
        and memory-related code where vulnerabilities could lead to memory corruption
        or memory management exploitation. Focus on C++ memory security best practices.
    """
    msg = f"""
C++ MEMORY THREAT ANALYSIS REQUEST

Function Context:
- C++ Memory Purpose: {function_explanation}
- File Location: {file_path}
- Memory Context: {memory_context}
- C++ Memory Threats to Evaluate: {', '.join(list_of_memory_threats or ['General security threats, Common vulnerabilities, OWASP Top 10'])}

C++ Memory Source Code to Analyze:
{function_body}

Please perform a comprehensive C++ memory security analysis focusing on the specified threats and provide detailed findings with memory-specific attack vector analysis, potential memory impact, and remediation guidance specific to C++ memory vulnerabilities and secure memory management practices.
"""

    return msg


async def cpp_concurrency_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the C++ concurrent function does, its purpose in multi-threading, and its role in concurrent operations. Should include threading operations, synchronization primitives, and any concurrency-related security behaviors."],
    function_body: Annotated[str, "The complete C++ source code of the concurrent function including all statements, variable assignments, control flow, function calls, threading operations, and any nested logic. This is the actual C++ concurrent code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'src/threading/ThreadManager.cpp', 'lib/concurrent/ThreadPool.cpp', 'app/async/AsyncProcessor.cpp'). Used for context and reporting."], 
    concurrency_context: Annotated[str, "Additional C++ concurrency context including the threading model (e.g., std::thread, pthread, OpenMP), synchronization primitives (e.g., mutex, semaphore, condition variable), and critical concurrent operations this function handles."],
    list_of_concurrency_threats: Annotated[list[str], "A comprehensive list of C++ concurrency-specific threats and vulnerabilities to check for during analysis. Each item should be a specific concurrency threat type (e.g., 'Race Conditions', 'Deadlocks', 'Livelocks', 'Data Races', 'Atomic Operation Violations', 'Memory Ordering Issues', 'Thread Safety Violations', 'Synchronization Bugs', 'Resource Contention', 'Priority Inversion', 'Starvation', 'Thread Leaks', 'Thread Pool Exhaustion', 'Lock Ordering Violations', 'Double Locking', 'Lock-Free Programming Errors', 'ABA Problems', 'Memory Reordering Issues', 'Cache Coherency Problems', 'False Sharing', 'Thread Local Storage Issues', 'Exception Safety in Threads', 'Signal Handling in Threads', 'Thread Cancellation Issues', 'Thread Cleanup Problems', etc.)."] = None
) -> str:
    """
    Analyze a C++ function for concurrency vulnerabilities and threats in multi-threaded operations.
    
    This function focuses specifically on C++ concurrency vulnerabilities, threading issues,
    and concurrency-specific attack vectors that could lead to race conditions, deadlocks,
    or exploitation of concurrent functionality.
    
    Args:
        function_explanation: Human-readable description of the C++ function's concurrency purpose and behavior
        function_body: Complete C++ source code of the concurrent function to be analyzed
        file_path: Full path to the C++ file containing the concurrent function for context
        concurrency_context: Additional C++ concurrency context and threading model information
        list_of_concurrency_threats: List of specific C++ concurrency threats to evaluate
        
    Returns:
        str: Detailed C++ concurrency analysis report including identified vulnerabilities,
             concurrency-specific attack vector analysis, potential concurrency impact, and remediation
             recommendations specific to C++ concurrency security.
             
    Example:
        result = await cpp_concurrency_threats(
            function_explanation="Thread-safe counter implementation with atomic operations and proper synchronization",
            function_body="class ThreadSafeCounter { std::atomic<int> count; public: void increment() { count++; } };",
            file_path="src/concurrent/ThreadSafeCounter.cpp",
            concurrency_context="C++11 atomic operations with std::atomic for thread-safe counter implementation",
            list_of_concurrency_threats=["Race Conditions", "Data Races", "Atomic Operation Violations", "Thread Safety Violations"]
        )
        
    Note:
        This function should be used for analyzing C++ concurrent functions, threading operations,
        and concurrency-related code where vulnerabilities could lead to race conditions
        or concurrency functionality exploitation. Focus on C++ concurrency security best practices.
    """
    msg = f"""
C++ CONCURRENCY THREAT ANALYSIS REQUEST

Function Context:
- C++ Concurrency Purpose: {function_explanation}
- File Location: {file_path}
- Concurrency Context: {concurrency_context}
- C++ Concurrency Threats to Evaluate: {', '.join(list_of_concurrency_threats or ['General security threats, Common vulnerabilities, OWASP Top 10'])}

C++ Concurrency Source Code to Analyze:
{function_body}

Please perform a comprehensive C++ concurrency security analysis focusing on the specified threats and provide detailed findings with concurrency-specific attack vector analysis, potential concurrency impact, and remediation guidance specific to C++ concurrency vulnerabilities and secure threading practices.
"""

    return msg
