package org.secretflow.secretpad.web.service.dev;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.secretflow.secretpad.persistence.entity.TeeAssetDO;
import org.secretflow.secretpad.persistence.repository.TeeAssetRepository;
import org.secretflow.secretpad.web.service.sandbox.TeeAssetRegistrar;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.util.ReflectionTestUtils;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class TeeMissingAssetRegistrationTest {
    @Test
    void missingMountedVersionIsRegisteredBeforeDispatch() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        TeeAssetRepository assets = mock(TeeAssetRepository.class);
        TeeAssetRegistrar registrar = mock(TeeAssetRegistrar.class);
        when(jdbc.queryForList(anyString(), eq("sandbox-1"), eq("asset-1")))
                .thenReturn(List.of(Map.of("asset_version", 1)));
        TeeAssetDO asset = TeeAssetDO.builder().upk(new TeeAssetDO.UPK("asset-1", "1")).build();
        when(assets.findById(any())).thenReturn(Optional.empty(), Optional.of(asset));
        TeeDevTaskDispatcher service = new TeeDevTaskDispatcher(jdbc, new ObjectMapper(), assets, null, null, null, null, null);
        ReflectionTestUtils.setField(service, "assetRegistrar", registrar);
        assertSame(asset, ReflectionTestUtils.invokeMethod(service, "latestAsset", "asset-1", Map.of(), "sandbox-1"));
        verify(registrar).ensureRegistered("asset-1", "sandbox-1");
        verify(assets, times(2)).findById(new TeeAssetDO.UPK("asset-1", "1"));
    }

    @Test
    void missingRequestedVersionDoesNotFallBackToAnotherVersion() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        TeeAssetRepository assets = mock(TeeAssetRepository.class);
        TeeAssetRegistrar registrar = mock(TeeAssetRegistrar.class);
        when(jdbc.queryForList(anyString(), eq("sandbox-1"), eq("asset-1")))
                .thenReturn(List.of(Map.of("asset_version", 2)));
        when(assets.findById(any())).thenReturn(Optional.empty());
        TeeDevTaskDispatcher service = new TeeDevTaskDispatcher(jdbc, new ObjectMapper(), assets, null, null, null, null, null);
        ReflectionTestUtils.setField(service, "assetRegistrar", registrar);
        assertThrows(RuntimeException.class, () -> ReflectionTestUtils.invokeMethod(service,
                "latestAsset", "asset-1", Map.of(), "sandbox-1"));
        verify(assets, never()).findByUpkAssetId(anyString());
    }
}
