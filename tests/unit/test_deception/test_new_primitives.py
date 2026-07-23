import pytest
from unittest.mock import AsyncMock
from adam.contracts.mutation import MutationResult
from adam.contracts.enums import MutationStatus
from adam.deception.primitives.process_lures import SimulateAVPresence
from adam.deception.primitives.filesystem_lures import PlantDecoyDocuments, PlantDecoyWallet
from adam.deception.primitives.network_lures import MountFakeNetworkShare, FabricateC2Response
from adam.deception.primitives.identity_lures import HideVMArtifacts, InjectFakeBrowserCreds
from adam.deception.primitives.registry_lures import PlantDecoyRunKey

@pytest.mark.asyncio
async def test_fabricate_c2_response():
    channel = AsyncMock()
    prim = FabricateC2Response(channel)
    mut = await prim.apply_async("sess", "corr", "dec", {})
    assert mut.status == MutationStatus.APPLIED
    assert len(mut.changes) == 1
    
    rev = await prim.revert_async(mut)
    assert rev.status == MutationStatus.REVERTED
    assert channel.apply_mutation.call_count == 2

@pytest.mark.asyncio
async def test_inject_fake_browser_creds():
    channel = AsyncMock()
    prim = InjectFakeBrowserCreds(channel)
    mut = await prim.apply_async("sess", "corr", "dec", {})
    assert mut.status == MutationStatus.APPLIED
    assert len(mut.changes) == 2
    
    rev = await prim.revert_async(mut)
    assert rev.status == MutationStatus.REVERTED
    assert channel.apply_mutation.call_count == 4

@pytest.mark.asyncio
async def test_plant_decoy_wallet():
    channel = AsyncMock()
    prim = PlantDecoyWallet(channel)
    mut = await prim.apply_async("sess", "corr", "dec", {})
    assert mut.status == MutationStatus.APPLIED
    assert len(mut.changes) == 2
    
    rev = await prim.revert_async(mut)
    assert rev.status == MutationStatus.REVERTED
    assert channel.apply_mutation.call_count == 4

@pytest.mark.asyncio
async def test_simulate_av_presence():
    channel = AsyncMock()
    prim = SimulateAVPresence(channel)
    mut = await prim.apply_async("sess", "corr", "dec", {})
    assert mut.status == MutationStatus.APPLIED
    assert len(mut.changes) == 2
    
    rev = await prim.revert_async(mut)
    assert rev.status == MutationStatus.REVERTED
    assert channel.apply_mutation.call_count == 4

@pytest.mark.asyncio
async def test_plant_decoy_documents():
    channel = AsyncMock()
    prim = PlantDecoyDocuments(channel)
    mut = await prim.apply_async("sess", "corr", "dec", {})
    assert mut.status == MutationStatus.APPLIED
    assert len(mut.changes) == 3
    
    rev = await prim.revert_async(mut)
    assert rev.status == MutationStatus.REVERTED
    assert channel.apply_mutation.call_count == 6

@pytest.mark.asyncio
async def test_mount_fake_network_share():
    channel = AsyncMock()
    prim = MountFakeNetworkShare(channel)
    mut = await prim.apply_async("sess", "corr", "dec", {})
    assert mut.status == MutationStatus.APPLIED
    assert len(mut.changes) == 2
    
    rev = await prim.revert_async(mut)
    assert rev.status == MutationStatus.REVERTED
    assert channel.apply_mutation.call_count == 4

@pytest.mark.asyncio
async def test_hide_vm_artifacts():
    channel = AsyncMock()
    prim = HideVMArtifacts(channel)
    mut = await prim.apply_async("sess", "corr", "dec", {})
    assert mut.status == MutationStatus.APPLIED
    assert len(mut.changes) == 1
    
    rev = await prim.revert_async(mut)
    assert rev.status == MutationStatus.REVERTED
    assert channel.apply_mutation.call_count == 2

@pytest.mark.asyncio
async def test_plant_decoy_run_key():
    channel = AsyncMock()
    prim = PlantDecoyRunKey(channel)
    mut = await prim.apply_async("sess", "corr", "dec", {})
    assert mut.status == MutationStatus.APPLIED
    assert len(mut.changes) == 1
    
    rev = await prim.revert_async(mut)
    assert rev.status == MutationStatus.REVERTED
    assert channel.apply_mutation.call_count == 2
