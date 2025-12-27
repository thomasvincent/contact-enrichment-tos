package com.contactenrichment.interfaces.api.exception;

import com.contactenrichment.infrastructure.security.TrustedSecurityKernel;
import com.contactenrichment.interfaces.api.dto.ErrorResponse;
import jakarta.persistence.OptimisticLockException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Global exception handler for REST API.
 *
 * Provides centralized exception handling with:
 * - Security-aware error responses (no sensitive data leakage)
 * - Comprehensive audit logging
 * - Standard error format
 * - Validation error details
 * - Proper HTTP status codes
 */
@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    /**
     * Handle validation errors from @Valid annotation.
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationErrors(
            MethodArgumentNotValidException ex,
            HttpServletRequest request) {

        List<ErrorResponse.ValidationError> validationErrors = ex.getBindingResult()
            .getAllErrors()
            .stream()
            .map(error -> {
                String fieldName = error instanceof FieldError
                    ? ((FieldError) error).getField()
                    : error.getObjectName();
                Object rejectedValue = error instanceof FieldError
                    ? ((FieldError) error).getRejectedValue()
                    : null;

                return ErrorResponse.ValidationError.builder()
                    .field(fieldName)
                    .message(error.getDefaultMessage())
                    .rejectedValue(rejectedValue)
                    .build();
            })
            .collect(Collectors.toList());

        ErrorResponse errorResponse = ErrorResponse.builder()
            .requestId(UUID.randomUUID())
            .timestamp(Instant.now())
            .status(HttpStatus.BAD_REQUEST.value())
            .error("Validation Failed")
            .message("Invalid request parameters")
            .path(request.getRequestURI())
            .validationErrors(validationErrors)
            .build();

        if (log.isWarnEnabled()) {
            log.warn("Validation error: {} validation failures on {}",
                validationErrors.size(), request.getRequestURI());
        }

        return ResponseEntity.badRequest().body(errorResponse);
    }

    // Human note: Map duplicate resource to HTTP 409 (Conflict) to match controller docs
    @ExceptionHandler(com.contactenrichment.application.exceptions.DuplicateResourceException.class)
    public ResponseEntity<ErrorResponse> handleDuplicate(
            com.contactenrichment.application.exceptions.DuplicateResourceException ex,
            HttpServletRequest request) {

        ErrorResponse errorResponse = ErrorResponse.builder()
            .requestId(UUID.randomUUID())
            .timestamp(Instant.now())
            .status(HttpStatus.CONFLICT.value())
            .error("Conflict")
            .message(ex.getMessage())
            .path(request.getRequestURI())
            .build();

        return ResponseEntity.status(HttpStatus.CONFLICT).body(errorResponse);
    }

    /**
     * Handle access denied exceptions from SecurityKernel.
     */
    @ExceptionHandler(TrustedSecurityKernel.AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDenied(
            TrustedSecurityKernel.AccessDeniedException ex,
            HttpServletRequest request) {

        ErrorResponse errorResponse = ErrorResponse.builder()
            .requestId(UUID.randomUUID())
            .timestamp(Instant.now())
            .status(HttpStatus.FORBIDDEN.value())
            .error("Access Denied")
            .message("You do not have permission to access this resource")
            .path(request.getRequestURI())
            .build();

        if (log.isWarnEnabled()) {
            log.warn("Access denied: {} on {}", ex.getMessage(), request.getRequestURI());
        }

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorResponse);
    }

    /**
     * Handle optimistic locking failures.
     */
    @ExceptionHandler(OptimisticLockException.class)
    public ResponseEntity<ErrorResponse> handleOptimisticLock(
            OptimisticLockException ex,
            HttpServletRequest request) {

        ErrorResponse errorResponse = ErrorResponse.builder()
            .requestId(UUID.randomUUID())
            .timestamp(Instant.now())
            .status(HttpStatus.CONFLICT.value())
            .error("Concurrent Modification")
            .message("The resource was modified by another request. Please retry.")
            .path(request.getRequestURI())
            .build();

        if (log.isWarnEnabled()) {
            log.warn("Optimistic lock exception on {}", request.getRequestURI());
        }

        return ResponseEntity.status(HttpStatus.CONFLICT).body(errorResponse);
    }

    /**
     * Handle illegal argument exceptions.
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgument(
            IllegalArgumentException ex,
            HttpServletRequest request) {

        ErrorResponse errorResponse = ErrorResponse.builder()
            .requestId(UUID.randomUUID())
            .timestamp(Instant.now())
            .status(HttpStatus.BAD_REQUEST.value())
            .error("Bad Request")
            .message("Invalid request: " + ex.getMessage())
            .path(request.getRequestURI())
            .build();

        if (log.isWarnEnabled()) {
            log.warn("Illegal argument: {} on {}", ex.getMessage(), request.getRequestURI());
        }

        return ResponseEntity.badRequest().body(errorResponse);
    }

    /**
     * Handle illegal state exceptions.
     */
    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<ErrorResponse> handleIllegalState(
            IllegalStateException ex,
            HttpServletRequest request) {

        ErrorResponse errorResponse = ErrorResponse.builder()
            .requestId(UUID.randomUUID())
            .timestamp(Instant.now())
            .status(HttpStatus.CONFLICT.value())
            .error("Invalid State")
            .message("Operation cannot be performed in current state")
            .path(request.getRequestURI())
            .build();

        if (log.isWarnEnabled()) {
            log.warn("Illegal state: {} on {}", ex.getMessage(), request.getRequestURI());
        }

        return ResponseEntity.status(HttpStatus.CONFLICT).body(errorResponse);
    }

    /**
     * Handle security exceptions.
     */
    @ExceptionHandler(SecurityException.class)
    public ResponseEntity<ErrorResponse> handleSecurityException(
            SecurityException ex,
            HttpServletRequest request) {

        ErrorResponse errorResponse = ErrorResponse.builder()
            .requestId(UUID.randomUUID())
            .timestamp(Instant.now())
            .status(HttpStatus.FORBIDDEN.value())
            .error("Security Violation")
            .message("Security policy violation detected")
            .path(request.getRequestURI())
            .build();

        if (log.isErrorEnabled()) {
            log.error("Security exception: {} on {}", ex.getMessage(), request.getRequestURI());
        }

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorResponse);
    }

    /**
     * Handle all other exceptions.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGenericException(
            Exception ex,
            HttpServletRequest request) {

        ErrorResponse errorResponse = ErrorResponse.builder()
            .requestId(UUID.randomUUID())
            .timestamp(Instant.now())
            .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
            .error("Internal Server Error")
            .message("An unexpected error occurred. Please contact support.")
            .path(request.getRequestURI())
            .build();

        if (log.isErrorEnabled()) {
            log.error("Unhandled exception on {}: {}",
                request.getRequestURI(), ex.getMessage(), ex);
        }

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
    }
}
