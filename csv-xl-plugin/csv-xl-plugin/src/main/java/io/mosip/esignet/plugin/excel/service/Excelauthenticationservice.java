package io.mosip.esignet.plugin.excel.service;

/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.RSAKey;
import io.mosip.esignet.api.dto.*;
import io.mosip.esignet.api.exception.KycAuthException;
import io.mosip.esignet.api.exception.KycExchangeException;
import io.mosip.esignet.api.exception.SendOtpException;
import io.mosip.esignet.api.spi.Authenticator;
import io.mosip.esignet.api.util.ErrorConstants;
import io.mosip.kernel.keymanagerservice.dto.AllCertificatesDataResponseDto;
import io.mosip.kernel.keymanagerservice.dto.CertificateDataResponseDto;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.signature.dto.JWTSignatureRequestDto;
import io.mosip.kernel.signature.dto.JWTSignatureResponseDto;
import io.mosip.kernel.signature.service.SignatureService;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import jakarta.annotation.PostConstruct;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * KBI Authenticator that validates challenge fields against rows of an Excel
 * (.xlsx/.xls) OR a CSV (.csv) file, instead of calling out to Sunbird-RC
 * (or any other registry). The file type is auto-detected from the
 * configured file's extension.
 *
 * Expected file format (same for both excel and csv):
 *  - Row 1 = header row. Header names must match the "field-details" id values
 *    configured below, plus one column for the unique entity id (entity-id-field).
 *  - Every subsequent row = one identity record.
 *
 * Example:
 *  | id        | fullName  | dob        | entityId |
 *  | 1234567890| John Doe  | 1990-01-01 | E-0001   |
 */
@ConditionalOnProperty(value = "mosip.esignet.integration.authenticator", havingValue = "ExcelAuthenticationService")
@Component
@Slf4j
public class ExcelAuthenticationService implements Authenticator {

    private static final String FIELD_ID_KEY = "id";

    @Value("#{${mosip.esignet.authenticator.excel.auth-factor.kbi.field-details}}")
    private List<Map<String, String>> fieldDetailList;

    @Value("${mosip.esignet.authenticator.excel.auth-factor.kbi.individual-id-field}")
    private String idField;

    @Value("${mosip.esignet.authenticator.excel.entity-id-field}")
    private String entityIdField;

    // Absolute path to the identity data file. Extension decides how it's read:
    // .xlsx / .xls -> parsed as Excel, .csv -> parsed as CSV.
    // e.g. /opt/esignet/config/identities.xlsx or /opt/esignet/config/identities.csv
    @Value("${mosip.esignet.authenticator.excel.file-path}")
    private String excelFilePath;

    // Name of the sheet to read. Defaults to the first sheet if left blank.
    @Value("${mosip.esignet.authenticator.excel.sheet-name:}")
    private String sheetName;

    @Value("#{${mosip.esignet.authenticator.excel.identity-openid-claims-mapping}}")
    private Map<String, String> oidcClaimsMapping;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private KeymanagerService keymanagerService;

    @Autowired
    private SignatureService signatureService;

    private static final Base64.Encoder urlSafeEncoder = Base64.getUrlEncoder().withoutPadding();

    public static final String APPLICATION_ID = "OIDC_PARTNER";

    // In-memory cache of the sheet: one Map per row, keyed by header name.
    private volatile List<Map<String, String>> rows = new ArrayList<>();

    private final ReadWriteLock cacheLock = new ReentrantReadWriteLock();

    @PostConstruct
    public void initialize() throws KycAuthException {
        log.info("Started to setup Excel Authenticator");

        if (fieldDetailList == null || fieldDetailList.isEmpty()) {
            log.error("Invalid configuration for field-details");
            throw new KycAuthException("excel authenticator field is not configured properly");
        }

        boolean individualIdFieldIsValid = fieldDetailList.stream()
                .anyMatch(field -> field.containsKey(FIELD_ID_KEY) && field.get(FIELD_ID_KEY).equals(idField));
        if (!individualIdFieldIsValid) {
            log.error("Invalid configuration: The 'individual-id-field' '{}' is not available in 'field-details'.", idField);
            throw new KycAuthException("Invalid configuration: individual-id-field is not available in field-details.");
        }

        try {
            loadIdentities();
        } catch (IOException e) {
            log.error("Failed to load identity data from {}", excelFilePath, e);
            throw new KycAuthException("excel authenticator could not load the identity data file");
        }
    }

    /**
     * Reads the whole identity file into memory as a list of header->value row maps.
     * Auto-detects Excel vs CSV from the file extension.
     * Call this again (e.g. via an admin endpoint or a scheduled task) whenever
     * the underlying file is updated, so changes get picked up without a restart.
     */
    public void loadIdentities() throws IOException {
        String lowerPath = excelFilePath.toLowerCase(Locale.ROOT);
        List<Map<String, String>> loadedRows;

        if (lowerPath.endsWith(".csv")) {
            loadedRows = loadFromCsv();
        } else if (lowerPath.endsWith(".xlsx") || lowerPath.endsWith(".xls")) {
            loadedRows = loadFromExcel();
        } else {
            throw new IOException("Unsupported file extension for: " + excelFilePath
                    + " (expected .xlsx, .xls, or .csv)");
        }

        cacheLock.writeLock().lock();
        try {
            this.rows = loadedRows;
            log.info("Loaded {} identity rows from {}", loadedRows.size(), excelFilePath);
        } finally {
            cacheLock.writeLock().unlock();
        }
    }

    private List<Map<String, String>> loadFromExcel() throws IOException {
        List<Map<String, String>> loadedRows = new ArrayList<>();

        try (InputStream is = new FileInputStream(excelFilePath);
             Workbook workbook = new XSSFWorkbook(is)) {

            Sheet sheet = (sheetName != null && !sheetName.isBlank())
                    ? workbook.getSheet(sheetName)
                    : workbook.getSheetAt(0);

            if (sheet == null) {
                throw new IOException("Sheet not found: " + sheetName);
            }

            Iterator<Row> rowIterator = sheet.iterator();
            if (!rowIterator.hasNext()) {
                throw new IOException("Sheet is empty, no header row found");
            }

            // Header row -> column index to field name
            Row headerRow = rowIterator.next();
            Map<Integer, String> headerByIndex = new HashMap<>();
            for (Cell cell : headerRow) {
                headerByIndex.put(cell.getColumnIndex(), cell.toString().trim());
            }

            DataFormatter formatter = new DataFormatter();
            while (rowIterator.hasNext()) {
                Row row = rowIterator.next();
                Map<String, String> rowMap = new HashMap<>();
                boolean rowHasData = false;
                for (Map.Entry<Integer, String> entry : headerByIndex.entrySet()) {
                    Cell cell = row.getCell(entry.getKey(), Row.MissingCellPolicy.RETURN_BLANK_AS_NULL);
                    String value = cell != null ? formatter.formatCellValue(cell).trim() : "";
                    if (!value.isEmpty()) {
                        rowHasData = true;
                    }
                    rowMap.put(entry.getValue(), value);
                }
                if (rowHasData) {
                    loadedRows.add(rowMap);
                }
            }
        }
        return loadedRows;
    }

    private List<Map<String, String>> loadFromCsv() throws IOException {
        List<Map<String, String>> loadedRows = new ArrayList<>();

        CSVFormat format = CSVFormat.DEFAULT.builder()
                .setHeader()
                .setSkipHeaderRecord(true)
                .setTrim(true)
                .setIgnoreEmptyLines(true)
                .build();

        try (Reader reader = new InputStreamReader(Files.newInputStream(Paths.get(excelFilePath)), StandardCharsets.UTF_8);
             CSVParser parser = format.parse(reader)) {

            for (CSVRecord record : parser) {
                Map<String, String> rowMap = new HashMap<>();
                boolean rowHasData = false;
                for (String header : parser.getHeaderNames()) {
                    String value = record.isSet(header) ? record.get(header).trim() : "";
                    if (!value.isEmpty()) {
                        rowHasData = true;
                    }
                    rowMap.put(header.trim(), value);
                }
                if (rowHasData) {
                    loadedRows.add(rowMap);
                }
            }
        }
        return loadedRows;
    }

    @Validated
    @Override
    public KycAuthResult doKycAuth(@NotBlank String relyingPartyId, @NotBlank String clientId,
                                   @NotNull @Valid KycAuthDto kycAuthDto) throws KycAuthException {

        log.info("Started to build kyc-auth request with transactionId : {} && clientId : {}",
                kycAuthDto.getTransactionId(), clientId);
        try {
            Optional<AuthChallenge> optionalAuthChallenge = kycAuthDto.getChallengeList().stream()
                    .filter(authChallenge -> Objects.equals(authChallenge.getAuthFactorType(), "KBI"))
                    .findFirst();
            if (optionalAuthChallenge.isPresent()) {
                return validateKnowledgeBasedAuth(kycAuthDto.getIndividualId(), optionalAuthChallenge.get());
            } else {
                throw new KycAuthException("invalid_challenge_type");
            }
        } catch (KycAuthException e) {
            throw e;
        } catch (Exception e) {
            log.error("KYC-auth failed with transactionId : {} && clientId : {}", kycAuthDto.getTransactionId(),
                    clientId, e);
        }
        throw new KycAuthException(ErrorConstants.AUTH_FAILED);
    }

    private KycAuthResult validateKnowledgeBasedAuth(String individualId, AuthChallenge authChallenge) throws KycAuthException {

        KycAuthResult kycAuthResult = new KycAuthResult();
        String encodedChallenge = authChallenge.getChallenge();

        byte[] decodedBytes = Base64.getUrlDecoder().decode(encodedChallenge);
        String challenge = new String(decodedBytes, StandardCharsets.UTF_8);

        try {
            Map<String, String> challengeMap = objectMapper.readValue(challenge, Map.class);

            // Build the field=expectedValue filter, same semantics as the Sunbird version.
            Map<String, String> filter = new HashMap<>();
            for (Map<String, String> fieldDetailMap : fieldDetailList) {
                String fieldName = fieldDetailMap.get(FIELD_ID_KEY);
                if (fieldName.equals(idField)) {
                    filter.put(fieldName, individualId);
                } else {
                    if (!challengeMap.containsKey(fieldName)) {
                        log.error("Field '{}' is missing in the challenge.", fieldName);
                        throw new KycAuthException(ErrorConstants.AUTH_FAILED);
                    }
                    filter.put(fieldName, challengeMap.get(fieldName));
                }
            }

            List<Map<String, String>> matches = findMatchingRows(filter);

            if (matches.size() == 1) {
                String entityId = matches.get(0).get(entityIdField);
                kycAuthResult.setKycToken(entityId);
                kycAuthResult.setPartnerSpecificUserToken(entityId);
                return kycAuthResult;
            } else {
                log.error("Excel search returned {} matches (expected exactly 1), authentication failed.", matches.size());
                throw new KycAuthException(ErrorConstants.AUTH_FAILED);
            }

        } catch (KycAuthException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to do the Authentication", e);
            throw new KycAuthException(ErrorConstants.AUTH_FAILED);
        }
    }

    /**
     * Case-sensitive exact match across every field in the filter, against the
     * in-memory row cache. Mirrors the "eq" filter semantics of the Sunbird version.
     */
    private List<Map<String, String>> findMatchingRows(Map<String, String> filter) {
        cacheLock.readLock().lock();
        try {
            List<Map<String, String>> result = new ArrayList<>();
            for (Map<String, String> row : rows) {
                boolean allMatch = true;
                for (Map.Entry<String, String> entry : filter.entrySet()) {
                    String rowValue = row.get(entry.getKey());
                    if (rowValue == null || !rowValue.equals(entry.getValue())) {
                        allMatch = false;
                        break;
                    }
                }
                if (allMatch) {
                    result.add(row);
                }
            }
            return result;
        } finally {
            cacheLock.readLock().unlock();
        }
    }

    @Override
    public KycExchangeResult doKycExchange(String relyingPartyId, String clientId, KycExchangeDto kycExchangeDto)
            throws KycExchangeException {
        String kycToken = kycExchangeDto.getKycToken();
        try {
            if (kycExchangeDto.getAcceptedClaims() == null) {
                kycExchangeDto.setAcceptedClaims(new ArrayList<>());
            }
            Set<String> uniqueClaims = new LinkedHashSet<>(kycExchangeDto.getAcceptedClaims());
            kycExchangeDto.setAcceptedClaims(new ArrayList<>(uniqueClaims));

            Map<String, String> row = findRowByEntityId(kycToken);
            if (row == null) {
                throw new KycExchangeException(ErrorConstants.DATA_EXCHANGE_FAILED);
            }

            Map<String, Object> kyc = buildKycDataBasedOnPolicy(row, kycExchangeDto.getAcceptedClaims());
            kyc.put("sub", kycExchangeDto.getIndividualId());

            String finalKyc;
            String userInfoResponseType = kycExchangeDto.getUserInfoResponseType();
            finalKyc = "JWE".equals(userInfoResponseType) ? getJWE(relyingPartyId, signKyc(kyc)) : signKyc(kyc);

            KycExchangeResult kycExchangeResult = new KycExchangeResult();
            kycExchangeResult.setEncryptedKyc(finalKyc);
            return kycExchangeResult;
        } catch (Exception e) {
            log.error("KYC exchange failed", e);
            throw new KycExchangeException(ErrorConstants.DATA_EXCHANGE_FAILED);
        }
    }

    private Map<String, String> findRowByEntityId(String entityId) {
        cacheLock.readLock().lock();
        try {
            for (Map<String, String> row : rows) {
                if (Objects.equals(row.get(entityIdField), entityId)) {
                    return row;
                }
            }
            return null;
        } finally {
            cacheLock.readLock().unlock();
        }
    }

    public Map<String, Object> buildKycDataBasedOnPolicy(Map<String, String> row, List<String> claims) {
        Map<String, Object> kyc = new HashMap<>();
        for (String claim : claims) {
            if (oidcClaimsMapping.containsKey(claim)) {
                String mappedKey = oidcClaimsMapping.get(claim);
                if (row.containsKey(mappedKey)) {
                    kyc.put(claim, row.get(mappedKey));
                }
            }
        }
        return kyc;
    }

    private String getJWE(String relyingPartyId, String signedJwt) throws Exception {
        JsonWebEncryption jsonWebEncryption = new JsonWebEncryption();
        jsonWebEncryption.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);
        jsonWebEncryption.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_GCM);
        jsonWebEncryption.setPayload(signedJwt);
        jsonWebEncryption.setContentTypeHeaderValue("JWT");
        RSAKey rsaKey = getRelyingPartyPublicKey(relyingPartyId);
        jsonWebEncryption.setKey(rsaKey.toPublicKey());
        jsonWebEncryption.setKeyIdHeaderValue(rsaKey.getKeyID());
        return jsonWebEncryption.getCompactSerialization();
    }

    private RSAKey getRelyingPartyPublicKey(String relyingPartyId) throws KycExchangeException {
        //TODO where to store relying-party public key
        throw new KycExchangeException(ErrorConstants.DATA_EXCHANGE_FAILED);
    }

    private String signKyc(Map<String, Object> kyc) throws JsonProcessingException {
        String payload = objectMapper.writeValueAsString(kyc);
        JWTSignatureRequestDto jwtSignatureRequestDto = new JWTSignatureRequestDto();
        jwtSignatureRequestDto.setApplicationId(APPLICATION_ID);
        jwtSignatureRequestDto.setReferenceId("");
        jwtSignatureRequestDto.setIncludePayload(true);
        jwtSignatureRequestDto.setIncludeCertificate(false);
        jwtSignatureRequestDto.setDataToSign(b64Encode(payload));
        jwtSignatureRequestDto.setIncludeCertHash(false);
        JWTSignatureResponseDto responseDto = signatureService.jwtSign(jwtSignatureRequestDto);
        return responseDto.getJwtSignedData();
    }

    public static String b64Encode(String value) {
        return urlSafeEncoder.encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public SendOtpResult sendOtp(String relyingPartyId, String clientId, SendOtpDto sendOtpDto)
            throws SendOtpException {
        throw new SendOtpException(ErrorConstants.NOT_IMPLEMENTED);
    }

    @Override
    public boolean isSupportedOtpChannel(String channel) {
        return false;
    }

    @Override
    public List<KycSigningCertificateData> getAllKycSigningCertificates() {
        List<KycSigningCertificateData> certs = new ArrayList<>();
        AllCertificatesDataResponseDto allCertificatesDataResponseDto = keymanagerService.getAllCertificates(APPLICATION_ID,
                Optional.empty());
        for (CertificateDataResponseDto dto : allCertificatesDataResponseDto.getAllCertificates()) {
            certs.add(new KycSigningCertificateData(dto.getKeyId(), dto.getCertificateData(),
                    dto.getExpiryAt(), dto.getIssuedAt()));
        }
        return certs;
    }
}