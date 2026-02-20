<?php

namespace App\Tests\Repository;

use PHPUnit\Framework\TestCase;

/**
 * RED TEST for SQL Injection vulnerability in UserRepository::getUserLogin()
 *
 * Tier 3 (Source Analysis): PHP runtime is not available in this environment,
 * so we cannot import the module or call getUserLogin() directly. This test
 * reads the source file and asserts that the query is parameterized (secure).
 * It FAILS on vulnerable code because the query uses raw string interpolation
 * instead of parameterized queries.
 *
 * Vulnerability: CWE-89 / CWE-798 — User-supplied $email is directly interpolated
 * into a raw SQL string in getUserLogin(), allowing SQL injection attacks such as:
 *   email: ' OR 1=1 --
 * This bypasses authentication entirely.
 *
 * The test asserts a security property (parameterized queries) that is MISSING,
 * so it FAILS on the current vulnerable code.
 */
class UserRepositorySqlInjectionTest extends TestCase
{
    private string $sourceCode;

    protected function setUp(): void
    {
        $filePath = __DIR__ . '/../../src/Repository/UserRepository.php';
        $this->assertFileExists($filePath, 'UserRepository.php must exist');
        $this->sourceCode = file_get_contents($filePath);
    }

    /**
     * Assert that getUserLogin does NOT use raw string interpolation in SQL.
     * Secure code should use parameterized queries (e.g., prepared statements with placeholders).
     *
     * This test FAILS because the current code contains:
     *   $rawSql = "SELECT * FROM user WHERE email = '$email' AND password = '$hashedPassword' LIMIT 1";
     * which is direct variable interpolation into SQL — a textbook SQL injection vulnerability.
     */
    public function testGetUserLoginDoesNotInterpolateVariablesIntoSql(): void
    {
        // Extract the getUserLogin method body
        $pattern = '/function\s+getUserLogin\s*\(.*?\)\s*:.*?\{(.*?)\n\s*\}/s';
        preg_match($pattern, $this->sourceCode, $matches);
        $this->assertNotEmpty($matches, 'getUserLogin method must exist in UserRepository');

        $methodBody = $matches[1];

        // SECURITY ASSERTION: The method must NOT contain direct variable interpolation
        // in SQL strings (e.g., '$email' or '$hashedPassword' inside a query string).
        // Secure code uses parameterized queries with placeholders like :email or ?.
        $hasDirectInterpolation = (bool) preg_match('/["\']SELECT\s.*\$/', $methodBody);

        $this->assertFalse(
            $hasDirectInterpolation,
            'VULNERABILITY DETECTED: getUserLogin() interpolates PHP variables directly into SQL string. '
            . 'This allows SQL injection. Use parameterized queries with bound parameters instead.'
        );
    }

    /**
     * Assert that the SQL query in getUserLogin uses parameterized placeholders.
     * Secure code should use :param or ? placeholders with bound parameters.
     *
     * This test FAILS because the current code does not use any parameterized placeholders.
     */
    public function testGetUserLoginUsesParameterizedQuery(): void
    {
        $pattern = '/function\s+getUserLogin\s*\(.*?\)\s*:.*?\{(.*?)\n\s*\}/s';
        preg_match($pattern, $this->sourceCode, $matches);
        $this->assertNotEmpty($matches, 'getUserLogin method must exist in UserRepository');

        $methodBody = $matches[1];

        // SECURITY ASSERTION: The method must use parameterized placeholders
        // (either named :param or positional ? placeholders)
        $usesNamedParams = (bool) preg_match('/:\w+/', $methodBody);
        $usesPositionalParams = (bool) preg_match('/\?\s/', $methodBody);
        $usesBindValue = (bool) preg_match('/bindValue|bindParam|setParameter/', $methodBody);

        $usesParameterizedQuery = $usesNamedParams || $usesPositionalParams || $usesBindValue;

        $this->assertTrue(
            $usesParameterizedQuery,
            'VULNERABILITY DETECTED: getUserLogin() does not use parameterized queries. '
            . 'SQL queries must use :param or ? placeholders with bound parameters to prevent SQL injection.'
        );
    }

    /**
     * Assert that the password is NOT hashed with the insecure md5() function.
     * Secure code should use password_hash() or a proper hashing algorithm (bcrypt, argon2).
     *
     * This test FAILS because the current code uses md5() for password hashing.
     */
    public function testGetUserLoginDoesNotUseMd5ForPasswordHashing(): void
    {
        $pattern = '/function\s+getUserLogin\s*\(.*?\)\s*:.*?\{(.*?)\n\s*\}/s';
        preg_match($pattern, $this->sourceCode, $matches);
        $this->assertNotEmpty($matches, 'getUserLogin method must exist in UserRepository');

        $methodBody = $matches[1];

        $usesMd5 = (bool) preg_match('/md5\s*\(/', $methodBody);

        $this->assertFalse(
            $usesMd5,
            'VULNERABILITY DETECTED: getUserLogin() uses md5() for password hashing. '
            . 'md5 is cryptographically broken. Use password_hash() with bcrypt or argon2 instead.'
        );
    }
}
