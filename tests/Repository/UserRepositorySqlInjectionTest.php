<?php

namespace App\Tests\Repository;

use PHPUnit\Framework\TestCase;

/**
 * RED TEST: Proves SQL Injection vulnerability in UserRepository::getUserLogin()
 *
 * The getUserLogin method constructs raw SQL by directly interpolating user input:
 *   $rawSql = "SELECT * FROM user WHERE email = '$email' AND password = '$hashedPassword' LIMIT 1";
 *
 * A secure implementation would use parameterized queries (prepared statements with bound parameters).
 *
 * This test reads the source file because the Symfony/Doctrine kernel cannot be bootstrapped
 * without a running database. The vulnerability is in how the SQL query is constructed — 
 * string interpolation instead of parameter binding — which is provable by source inspection.
 */
class UserRepositorySqlInjectionTest extends TestCase
{
    private string $sourceCode;

    protected function setUp(): void
    {
        $filePath = __DIR__ . '/../../src/Repository/UserRepository.php';
        $this->assertTrue(file_exists($filePath), 'UserRepository.php must exist');
        $this->sourceCode = file_get_contents($filePath);
    }

    /**
     * Test that getUserLogin uses parameterized queries instead of string interpolation.
     *
     * SECURE code would use parameter binding like:
     *   $stmt = $conn->prepare("SELECT * FROM user WHERE email = :email AND password = :password LIMIT 1");
     *   $stmt->executeQuery(['email' => $email, 'password' => $hashedPassword]);
     *
     * VULNERABLE code directly interpolates variables into the SQL string:
     *   $rawSql = "SELECT * FROM user WHERE email = '$email' AND ...";
     *
     * This test FAILS on the current vulnerable code because it asserts the security
     * property (parameterized queries) is present, but it's missing.
     */
    public function testGetUserLoginUsesParameterizedQueries(): void
    {
        // Extract the getUserLogin method body
        $methodPattern = '/function\s+getUserLogin\s*\([^)]*\)[^{]*\{(.*?)\n\s*\}/s';
        preg_match($methodPattern, $this->sourceCode, $matches);

        $this->assertNotEmpty($matches, 'getUserLogin method must exist');
        $methodBody = $matches[1];

        // SECURITY ASSERTION: The query must NOT use string interpolation with variables
        // A secure implementation would use placeholders (:param or ?) instead of '$variable'
        $usesStringInterpolation = (bool) preg_match('/["\']SELECT.*\$\w+.*["\']/', $methodBody);

        $this->assertFalse(
            $usesStringInterpolation,
            'VULNERABILITY: getUserLogin() uses string interpolation to build SQL queries. '
            . 'This creates a SQL injection vulnerability. Use parameterized queries with '
            . 'bound parameters (e.g., :email, :password placeholders) instead of directly '
            . 'interpolating $email and $hashedPassword into the query string.'
        );
    }

    /**
     * Test that the SQL query in getUserLogin uses parameter placeholders.
     *
     * Secure code should use named parameters (:email, :password) or positional 
     * parameters (?) and pass values via executeQuery() parameter array.
     */
    public function testGetUserLoginUsesBindParameters(): void
    {
        $methodPattern = '/function\s+getUserLogin\s*\([^)]*\)[^{]*\{(.*?)\n\s*\}/s';
        preg_match($methodPattern, $this->sourceCode, $matches);

        $this->assertNotEmpty($matches, 'getUserLogin method must exist');
        $methodBody = $matches[1];

        // SECURITY ASSERTION: The SQL should contain parameter placeholders
        $usesNamedParams = (bool) preg_match('/:[a-zA-Z]+/', $methodBody);
        $usesPositionalParams = (bool) preg_match('/\?\s*/', $methodBody) 
            && (bool) preg_match('/executeQuery\s*\(\s*\[/', $methodBody);

        // Check if executeQuery is called with a non-empty parameter array
        $executesWithParams = (bool) preg_match('/executeQuery\s*\(\s*\[\s*[\'"]/', $methodBody)
            || (bool) preg_match('/executeQuery\s*\(\s*\[\s*\$/', $methodBody);

        $usesParameterizedQuery = ($usesNamedParams || $usesPositionalParams) && $executesWithParams;

        $this->assertTrue(
            $usesParameterizedQuery,
            'VULNERABILITY: getUserLogin() does not use parameterized queries. '
            . 'The method should use parameter placeholders (:email, :password or ?) '
            . 'and pass values through the executeQuery() parameter array to prevent SQL injection.'
        );
    }

    /**
     * Test that executeQuery receives actual bound parameters (non-empty array).
     *
     * Currently the code calls: $stmt->executeQuery([])
     * Secure code should call: $stmt->executeQuery(['email' => $email, 'password' => $hashedPassword])
     */
    public function testExecuteQueryReceivesBoundParameters(): void
    {
        $methodPattern = '/function\s+getUserLogin\s*\([^)]*\)[^{]*\{(.*?)\n\s*\}/s';
        preg_match($methodPattern, $this->sourceCode, $matches);

        $this->assertNotEmpty($matches, 'getUserLogin method must exist');
        $methodBody = $matches[1];

        // SECURITY ASSERTION: executeQuery should NOT be called with an empty array
        $executesWithEmptyArray = (bool) preg_match('/executeQuery\s*\(\s*\[\s*\]\s*\)/', $methodBody);

        $this->assertFalse(
            $executesWithEmptyArray,
            'VULNERABILITY: executeQuery() is called with an empty parameter array []. '
            . 'This confirms user input is concatenated directly into the SQL string instead '
            . 'of being passed as bound parameters. The parameters should be passed through '
            . 'the executeQuery() call to prevent SQL injection.'
        );
    }
}
