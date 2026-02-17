<?php

namespace App\Tests\Repository;

use PHPUnit\Framework\TestCase;

/**
 * RED test: Proves CWE-798 / SQL-injection vulnerability in UserRepository::getUserLogin().
 *
 * The method builds a raw SQL query by directly interpolating $email and the MD5-hashed
 * password into a string literal.  This violates two security properties at once:
 *
 *  1. Credentials (passwords, even hashed ones) must never be embedded via string
 *     interpolation into SQL – they must be passed through parameterised / prepared
 *     statement placeholders so that the driver handles quoting.
 *
 *  2. The hashing algorithm (MD5) is hard-wired in the source, which means the
 *     credential-handling logic is itself a hardcoded secret/policy (CWE-798).
 *
 * A SECURE implementation would use a parameterised query such as:
 *   "SELECT * FROM user WHERE email = :email AND password = :password LIMIT 1"
 * and bind $email / $hashedPassword as named parameters.
 *
 * Because the current code is INSECURE, every assertion in this test FAILS,
 * proving the vulnerability exists.  After the fix these assertions will PASS.
 *
 * NOTE: PHP is not available in this CI environment so Tier-1 (runtime) testing
 * is not possible.  This Tier-3 source-analysis test is therefore the appropriate
 * fallback, and IS the canonical proof for a hardcoded-credentials / string-
 * interpolation finding (the vulnerability is inherently a source-level property).
 */
class UserRepositoryHardcodedCredentialsTest extends TestCase
{
    private string $sourceFile;
    private string $sourceCode;

    protected function setUp(): void
    {
        $this->sourceFile = dirname(__DIR__, 2) . '/src/Repository/UserRepository.php';
        $this->assertTrue(
            file_exists($this->sourceFile),
            "Source file not found: {$this->sourceFile}"
        );
        $this->sourceCode = file_get_contents($this->sourceFile);
    }

    // -------------------------------------------------------------------------
    // 1. The query MUST use named placeholders, not string interpolation
    // -------------------------------------------------------------------------

    /**
     * A secure implementation must NOT embed variables directly in the SQL
     * string via PHP string interpolation (the "$variable" pattern inside
     * a double-quoted SQL literal).
     *
     * FAILS on vulnerable code because '$email' and '$hashedPassword' are
     * interpolated directly into the query string.
     */
    public function testSqlQueryDoesNotInterpolateVariables(): void
    {
        // Matches patterns like:  "... '$email' ..."  or  "... '$hashedPassword' ..."
        // i.e. a PHP variable expanded inside a double-quoted SQL string.
        $hasInterpolatedVariable = (bool) preg_match(
            '/SELECT\s.*WHERE.*\'\$\w+\'/',
            $this->sourceCode
        );

        $this->assertFalse(
            $hasInterpolatedVariable,
            'VULNERABILITY (CWE-798 / SQL-injection): getUserLogin() embeds ' .
            'credentials directly into the SQL string via PHP variable interpolation ' .
            '(e.g. \'$email\' and \'$hashedPassword\'). ' .
            'Use named placeholders (:email, :password) and bind the values separately.'
        );
    }

    /**
     * A secure implementation MUST use named (or positional) placeholders so
     * that the database driver handles value escaping.
     *
     * FAILS on vulnerable code because no ":" placeholder appears in the query.
     */
    public function testSqlQueryUsesNamedPlaceholders(): void
    {
        // A parameterised query contains at least one ":param" placeholder.
        $hasNamedPlaceholder = (bool) preg_match(
            '/SELECT\s.*WHERE.*:\w+/',
            $this->sourceCode
        );

        $this->assertTrue(
            $hasNamedPlaceholder,
            'VULNERABILITY (CWE-798): getUserLogin() does not use named ' .
            'placeholders (e.g. :email, :password) in its SQL query. ' .
            'Credentials must be bound via parameterised statements, not interpolated.'
        );
    }

    // -------------------------------------------------------------------------
    // 2. Hard-wired MD5 credential hashing must be replaced
    // -------------------------------------------------------------------------

    /**
     * Passwords must not be hashed with MD5 hard-coded in the repository.
     * The hashing algorithm should come from a configurable/injectable service
     * (e.g. Symfony's PasswordHasherInterface), not a raw md5() call.
     *
     * FAILS on vulnerable code because `md5($password)` appears literally.
     */
    public function testNoHardcodedMd5PasswordHashing(): void
    {
        $hasMd5Call = (bool) preg_match('/\bmd5\s*\(\s*\$password\s*\)/', $this->sourceCode);

        $this->assertFalse(
            $hasMd5Call,
            'VULNERABILITY (CWE-798 / hardcoded credential policy): getUserLogin() ' .
            'hard-codes MD5 as the password hashing algorithm via md5($password). ' .
            'Use an injectable PasswordHasherInterface so the algorithm is not ' .
            'embedded in source code.'
        );
    }

    // -------------------------------------------------------------------------
    // 3. Raw SQL construction via string concatenation/interpolation is forbidden
    // -------------------------------------------------------------------------

    /**
     * The method must not build raw SQL by assigning a string literal that
     * contains interpolated values to a $rawSql variable and then preparing it.
     *
     * FAILS on vulnerable code because exactly this pattern exists.
     */
    public function testNoRawSqlVariableWithInterpolatedCredentials(): void
    {
        // Matches:  $rawSql = "SELECT ... '$email' ... '$hashedPassword' ...";
        $hasRawSqlPattern = (bool) preg_match(
            '/\$rawSql\s*=\s*"SELECT[^"]*\'\$\w+\'[^"]*"/s',
            $this->sourceCode
        );

        $this->assertFalse(
            $hasRawSqlPattern,
            'VULNERABILITY (CWE-798 / SQL-injection): getUserLogin() constructs a ' .
            'raw SQL string ($rawSql) with credentials interpolated inside single-quoted ' .
            'string segments. This is unsafe. Use a parameterised query builder or ' .
            'Doctrine\'s QueryBuilder with bound parameters.'
        );
    }
}
