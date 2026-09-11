package io.mosip.esignet.plugin.sunbirdrc.dto;
import lombok.Data;
import java.util.List;
import java.util.Map;
@Data
public class RegistrySearchResponseDto {
    private int totalCount;
    private List<Map<String, Object>> data;
}

