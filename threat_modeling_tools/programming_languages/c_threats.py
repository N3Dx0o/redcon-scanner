from typing import Annotated


async def c_general_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the C function does, its purpose, and its role in the application. Should include C-specific operations, memory management, and any C-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the C function including all statements, variable assignments, control flow, function calls, C operations, and any nested logic. This is the actual C code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'src/main.c', 'lib/string_utils.c', 'app/network_handler.c'). Used for context and reporting."], 
    c_context: Annotated[str, "Additional C context including the C standard used (e.g., C89, C99, C11, C17), compiler flags, and critical C operations this function handles."],
    list_of_c_threats: Annotated[list[str], "A comprehensive list of C-specific threats and vulnerabilities to check for during analysis. Each item should be a specific C threat type (e.g., 'Buffer Overflow', 'Buffer Underflow', 'Stack Overflow', 'Heap Overflow', 'Use-After-Free', 'Double-Free', 'Memory Leaks', 'Dangling Pointers', 'Null Pointer Dereference', 'Wild Pointers', 'Stale Pointers', 'Memory Corruption', 'Heap Spraying', 'Stack Smashing', 'Return Address Overwrite', 'Function Pointer Overwrite', 'Virtual Table Corruption', 'Memory Exhaustion', 'Fragmentation Attacks', 'Uninitialized Memory Access', 'Memory Disclosure', 'ASLR Bypass', 'DEP Bypass', 'ROP Chain Construction', 'JOP Attacks', 'COOP Attacks', 'Integer Overflow', 'Integer Underflow', 'Type Confusion', 'Format String Vulnerabilities', 'Integer Conversion Issues', 'Array Bounds Violations', 'Uninitialized Variables', 'Race Conditions', 'Thread Safety Issues', 'Exception Safety Violations', 'Resource Leaks', 'Input Validation Flaws', 'Command Injection', 'Path Traversal', 'Deserialization Vulnerabilities', 'Cryptographic Implementation Bugs', 'Weak Random Number Generation', 'Cryptographic Constant-Time Violations', 'Memory Disclosure in Crypto Operations', 'Cryptographic Nonce Issues', 'Salt Generation Problems', 'Password Hashing Vulnerabilities', 'Cryptographic Key Recovery', 'Cryptographic Signature Forgery', 'Cryptographic Authentication Bypass', 'Cryptographic Authorization Issues', 'Cryptographic Session Management', 'Cryptographic Input Validation', 'Cryptographic Output Encoding', 'Cryptographic Error Handling', 'Cryptographic Logging Issues', 'Cryptographic Configuration Issues', 'Cryptographic Dependency Issues', 'Cryptographic Supply Chain Issues', 'Cryptographic Import Issues', 'Cryptographic Module Issues', 'Cryptographic Package Issues', 'Cryptographic Virtual Environment Issues', 'Cryptographic Environment Issues', 'Cryptographic Secret Management', 'Cryptographic Random Number Issues', 'Cryptographic Hash Issues', 'Cryptographic Buffer Issues', 'Cryptographic Integer Issues', 'Cryptographic Format String Issues', 'Cryptographic Eval Issues', 'Cryptographic Exec Issues', 'Cryptographic Compile Issues', 'Cryptographic Open Issues', 'Cryptographic Input Issues', 'Cryptographic Output Issues', 'Cryptographic Network Issues', 'Cryptographic File Issues', 'Cryptographic Process Issues', 'Cryptographic System Issues', etc.)."] = None
) -> str:
    """
    Analyze a C function for C-specific security vulnerabilities and threats.
    
    This function focuses specifically on C vulnerabilities, C implementation flaws,
    and C-specific attack vectors that could lead to memory corruption,
    code execution, or exploitation of C functionality.
    
    Args:
        function_explanation: Human-readable description of the C function's purpose and behavior
        function_body: Complete source code of the C function to be analyzed
        file_path: Full path to the file containing the C function for context
        c_context: Additional C context and C implementation information
        list_of_c_threats: List of specific C threats to evaluate
        
    Returns:
        str: Detailed C analysis report including identified vulnerabilities,
             C-specific attack vector analysis, potential C impact, and remediation
             recommendations specific to C security.
             
    Example:
        result = await c_general_threats(
            function_explanation="String copy function with buffer size validation",
            function_body="void strcpy_safe(char *dest, const char *src, size_t dest_size) { ... }",
            file_path="src/string_utils.c",
            c_context="C99 string manipulation with bounds checking and null termination",
            list_of_c_threats=["Buffer Overflow", "Buffer Underflow", "Null Pointer Dereference", "Memory Leaks"]
        )
        
    Note:
        This function should be used for analyzing C functions, C implementations,
        and C-specific code where vulnerabilities could lead to C compromise
        or C functionality exploitation. Focus on C security best practices.
    """
    msg = f"""
C GENERAL THREAT ANALYSIS REQUEST

Function Context:
- C Purpose: {function_explanation}
- File Location: {file_path}
- C Context: {c_context}
- C Threats to Evaluate: {', '.join(list_of_c_threats or ['General security threats, Common vulnerabilities, OWASP Top 10'])}

C Source Code to Analyze:
{function_body}

Please perform a comprehensive C security analysis focusing on the specified threats and provide detailed findings with C-specific attack vector analysis, potential C impact, and remediation guidance specific to C vulnerabilities and secure C development practices.
"""

    return msg


async def c_memory_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the C memory function does, its purpose in memory management, and its role in handling dynamic memory operations. Should include memory allocation, deallocation, pointer operations, and any memory-related security behaviors."],
    function_body: Annotated[str, "The complete source code of the C memory function including all statements, variable assignments, control flow, function calls, memory operations, pointer manipulations, and any nested logic. This is the actual C memory code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'src/memory_manager.c', 'lib/buffer_utils.c', 'app/data_processor.c'). Used for context and reporting."], 
    memory_context: Annotated[str, "Additional C memory context including the memory management approach (e.g., manual allocation, custom allocators), memory patterns used (e.g., stack allocation, heap allocation), and critical memory operations this function handles."],
    list_of_memory_threats: Annotated[list[str], "A comprehensive list of C memory-specific threats and vulnerabilities to check for during analysis. Each item should be a specific memory threat type (e.g., 'Buffer Overflow', 'Buffer Underflow', 'Stack Overflow', 'Heap Overflow', 'Use-After-Free', 'Double-Free', 'Memory Leaks', 'Dangling Pointers', 'Null Pointer Dereference', 'Wild Pointers', 'Stale Pointers', 'Memory Corruption', 'Heap Spraying', 'Stack Smashing', 'Return Address Overwrite', 'Function Pointer Overwrite', 'Virtual Table Corruption', 'Memory Exhaustion', 'Fragmentation Attacks', 'Uninitialized Memory Access', 'Memory Disclosure', 'ASLR Bypass', 'DEP Bypass', 'ROP Chain Construction', 'JOP Attacks', 'COOP Attacks', 'Integer Overflow', 'Integer Underflow', 'Type Confusion', 'Format String Vulnerabilities', 'Integer Conversion Issues', 'Array Bounds Violations', 'Uninitialized Variables', 'Race Conditions', 'Thread Safety Issues', 'Exception Safety Violations', 'Resource Leaks', 'Input Validation Flaws', 'Command Injection', 'Path Traversal', 'Deserialization Vulnerabilities', 'Cryptographic Implementation Bugs', 'Weak Random Number Generation', 'Cryptographic Constant-Time Violations', 'Memory Disclosure in Crypto Operations', 'Cryptographic Nonce Issues', 'Salt Generation Problems', 'Password Hashing Vulnerabilities', 'Cryptographic Key Recovery', 'Cryptographic Signature Forgery', 'Cryptographic Authentication Bypass', 'Cryptographic Authorization Issues', 'Cryptographic Session Management', 'Cryptographic Input Validation', 'Cryptographic Output Encoding', 'Cryptographic Error Handling', 'Cryptographic Logging Issues', 'Cryptographic Configuration Issues', 'Cryptographic Dependency Issues', 'Cryptographic Supply Chain Issues', 'Cryptographic Import Issues', 'Cryptographic Module Issues', 'Cryptographic Package Issues', 'Cryptographic Virtual Environment Issues', 'Cryptographic Environment Issues', 'Cryptographic Secret Management', 'Cryptographic Random Number Issues', 'Cryptographic Hash Issues', 'Cryptographic Buffer Issues', 'Cryptographic Integer Issues', 'Cryptographic Format String Issues', 'Cryptographic Eval Issues', 'Cryptographic Exec Issues', 'Cryptographic Compile Issues', 'Cryptographic Open Issues', 'Cryptographic Input Issues', 'Cryptographic Output Issues', 'Cryptographic Network Issues', 'Cryptographic File Issues', 'Cryptographic Process Issues', 'Cryptographic System Issues', etc.)."] = None
) -> str:
    """
    Analyze a C memory function for memory-specific vulnerabilities and threats.
    
    This function focuses specifically on C memory vulnerabilities, memory management issues,
    and memory-specific attack vectors that could lead to memory corruption,
    code execution, or exploitation of memory functionality.
    
    Args:
        function_explanation: Human-readable description of the C memory function's purpose and behavior
        function_body: Complete source code of the C memory function to be analyzed
        file_path: Full path to the file containing the C memory function for context
        memory_context: Additional C memory context and memory management approach information
        list_of_memory_threats: List of specific memory threats to evaluate
        
    Returns:
        str: Detailed C memory analysis report including identified vulnerabilities,
             memory-specific attack vector analysis, potential memory impact, and remediation
             recommendations specific to C memory security.
             
    Example:
        result = await c_memory_threats(
            function_explanation="Dynamic buffer allocation and management for user input processing",
            function_body="char* allocate_buffer(size_t size) { return malloc(size); }",
            file_path="src/memory_manager.c",
            memory_context="Manual memory management with malloc/free and custom buffer handling",
            list_of_memory_threats=["Buffer Overflow", "Memory Leaks", "Use-After-Free", "Double-Free"]
        )
        
    Note:
        This function should be used for analyzing C memory functions, pointer operations,
        and memory-related code where vulnerabilities could lead to memory corruption
        or memory management exploitation. Focus on C memory security best practices.
    """
    msg = f"""
C MEMORY THREAT ANALYSIS REQUEST

Function Context:
- C Memory Purpose: {function_explanation}
- File Location: {file_path}
- Memory Context: {memory_context}
- Memory Threats to Evaluate: {', '.join(list_of_memory_threats or ['General security threats, Common vulnerabilities, OWASP Top 10'])}

C Memory Source Code to Analyze:
{function_body}

Please perform a comprehensive C memory security analysis focusing on the specified threats and provide detailed findings with memory-specific attack vector analysis, potential memory impact, and remediation guidance specific to C memory vulnerabilities and secure memory management practices.
"""

    return msg
