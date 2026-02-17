<?php

/**
 * RED TEST — CWE-798 / SQL Injection in UserRepository::getUserLogin
 *
 * Behavioral testing (Tier 1) is not possible because PHP is not available in the
 * CI test environment. This test falls back to source analysis (Tier 3) to prove
 * the vulnerability exists.
 *
 * The vulnerability: UserRepository::getUserLogin() at line 74 constructs a raw SQL
 * query by interpolating user-supplied values directly into the query string:
 *
 *   $rawSql = "SELECT * FROM user WHERE email = '$email' AND password = '$hashedPassword' LIMIT 1";
 *
 * This creates a critical SQL injection vulnerability. Additionally, MD5 is used for
 * password hashing, which is a weak/hardcoded credential handling approach.
 *
 * SECURE code would use parameterized queries (prepared statements with bound parameters)
 * and a proper password hashing algorithm (e.g., bcrypt/argon2).
 *
 * This test asserts that the security properties ARE present. It FAILS on the current
 * vulnerable code (because they are missing) and will PASS after the fix is applied.
 */

namespace App\Tests\Repository;

use PHPUnit\Framework\TestCase;

class UserRepositorySqlInjectionTest extends TestCase
{
    private string $sourceCode;

    protected function setUp(): void
    {
        $filePath = __DIR__ . '/../../src/Repository/UserRepository.php';
        $this->assertFileExists($filePath, 'UserRepository.php source file must exist');
        $this->sourceCode = file_get_contents($filePath);
    }

    /**
     * Test that getUserLogin uses parameterized queries instead of string interpolation.
     *
     * SECURE code uses prepared statements with bound parameters, e.g.:
     *   $rawSql = "SELECT * FROM user WHERE email = :email AND password = :password LIMIT 1";
     *   $stmt->executeQuery(['email' => $email, 'password' => $hashedPassword]);
     *
     * VULNERABLE code interpolates variables directly into SQL:
     *   $rawSql = "SELECT * FROM user WHERE email = '$email' AND ...";
     *
     * This test FAILS on vulnerable code because string interpolation is present.
     */
    public function testGetUserLoginUsesParameterizedQueries(): void
    {
        // Extract the getUserLogin method body
        $methodPattern = '/function\s+getUserLogin\s*\([^)]*\)[^{]*\{(.*?)\n\s*\}/s';
        $this->assertMatchesRegularExpression($methodPattern, $this->sourceCode, 'getUserLogin method must exist');

        preg_match($methodPattern, $this->sourceCode, $matches);
        $methodBody = $matches[1];

        // SECURITY ASSERTION: The SQL query must NOT contain PHP variable interpolation
        // inside the query string. Secure code uses parameter placeholders (:param or ?).
        // Check that the method body does not contain a SQL string with embedded $ variables
        $hasSqlWithInterpolation = (bool) preg_match('/=\s*"SELECT[^"]*\$/', $methodBody);
        $this->assertFalse(
            $hasSqlWithInterpolation,
            'SQL query must not contain interpolated PHP variables — use parameterized queries instead. ' .
            'Found raw variable interpolation in SQL string, which is vulnerable to SQL injection (CWE-89/CWE-798).'
        );
    }

    /**
     * Test that getUserLogin does not use MD5 for password hashing.
     *
     * SECURE code uses password_hash() / password_verify() with bcrypt or argon2.
     * VULNERABLE code uses md5() which is cryptographically broken for passwords.
     *
     * This test FAILS on vulnerable code because md5() is used.
     */
    public function testGetUserLoginDoesNotUseMd5ForPasswordHashing(): void
    {
        $methodPattern = '/function\s+getUserLogin\s*\([^)]*\)[^{]*\{(.*?)\n\s*\}/s';
        preg_match($methodPattern, $this->sourceCode, $matches);
        $methodBody = $matches[1];

        // SECURITY ASSERTION: Password hashing must not use MD5
        $this->assertDoesNotMatchRegularExpression(
            '/md5\s*\(/',
            $methodBody,
            'Password hashing must not use MD5 — use password_hash() with PASSWORD_BCRYPT or PASSWORD_ARGON2ID instead. ' .
            'MD5 is a weak hashing algorithm unsuitable for credential storage (CWE-798).'
        );
    }

    /**
     * Test that executeQuery is called with bound parameters (non-empty array).
     *
     * SECURE code passes parameters to executeQuery:
     *   $stmt->executeQuery(['email' => $email, 'password' => $hashedPassword]);
     *
     * VULNERABLE code passes an empty array:
     *   $stmt->executeQuery([]);
     *
     * This test FAILS on vulnerable code because parameters are not bound.
     */
    public function testExecuteQueryUsesBindParameters(): void
    {
        $methodPattern = '/function\s+getUserLogin\s*\([^)]*\)[^{]*\{(.*?)\n\s*\}/s';
        preg_match($methodPattern, $this->sourceCode, $matches);
        $methodBody = $matches[1];

        // SECURITY ASSERTION: executeQuery must NOT be called with an empty array
        // Secure code binds parameters: executeQuery(['email' => $email, ...])
        $this->assertDoesNotMatchRegularExpression(
            '/executeQuery\s*\(\s*\[\s*\]\s*\)/',
            $methodBody,
            'executeQuery() must be called with bound parameters, not an empty array. ' .
            'Passing an empty array means no parameters are bound, indicating raw SQL interpolation.'
        );
    }
}
