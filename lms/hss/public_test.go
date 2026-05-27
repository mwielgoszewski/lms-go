package hss_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trailofbits/lms-go/lms/common"
	"github.com/trailofbits/lms-go/lms/hss"
	"github.com/trailofbits/lms-go/lms/lms"
)

func TestHssPublicKeyRoundTrip(t *testing.T) {
	// Build an LMS public key to embed.
	lmsPriv, err := lms.NewPrivateKey(common.LMS_SHA256_M32_H5, common.LMOTS_SHA256_N32_W8)
	assert.NoError(t, err)
	lmsPub := lmsPriv.Public()

	hssPub, err := hss.NewPublicKey(2, lmsPub)
	assert.NoError(t, err)

	encoded := hssPub.ToBytes()
	// 4-byte L + LMS public key (24 + M = 24 + 32 = 56 bytes) = 60 bytes
	assert.Equal(t, 60, len(encoded))

	decoded, err := hss.HssPublicKeyFromBytes(encoded)
	assert.NoError(t, err)
	assert.Equal(t, encoded, decoded.ToBytes())
}

func TestHssPublicKeyRejectsInvalidLevels(t *testing.T) {
	lmsPriv, err := lms.NewPrivateKey(common.LMS_SHA256_M32_H5, common.LMOTS_SHA256_N32_W8)
	assert.NoError(t, err)
	lmsPub := lmsPriv.Public()

	_, err = hss.NewPublicKey(0, lmsPub)
	assert.Error(t, err)

	_, err = hss.NewPublicKey(9, lmsPub)
	assert.Error(t, err)
}

func TestHssPublicKeyFromBytesShort(t *testing.T) {
	for i := 0; i < 4; i++ {
		_, err := hss.HssPublicKeyFromBytes(make([]byte, i))
		assert.Error(t, err)
	}
}

// TestHssKATFromRFC8554 verifies the L=2 HSS test vector from
// RFC 8554 Appendix F ("Test Case 2"). Top tree: LMS_SHA256_M32_H10 +
// LMOTS_SHA256_N32_W4. Bottom tree: LMS_SHA256_M32_H5 + LMOTS_SHA256_N32_W8.
func TestHssKATFromRFC8554(t *testing.T) {
	const (
		msgHex = "54686520656e756d65726174696f6e20" +
			"696e2074686520436f6e737469747574" +
			"696f6e2c206f66206365727461696e20" +
			"7269676874732c207368616c6c206e6f" +
			"7420626520636f6e7374727565642074" +
			"6f2064656e79206f7220646973706172" +
			"616765206f7468657273207265746169" +
			"6e6564206279207468652070656f706c" +
			"652e0a"

		pubHex = "00000002" +
			"00000006" +
			"00000003" +
			"d08fabd4a2091ff0a8cb4ed834e74534" +
			"32a58885cd9ba0431235466bff9651c6" +
			"c92124404d45fa53cf161c28f1ad5a8e"

		sigHex = "00000001" +
			// sig[0]: LMS signature under the top tree
			"00000003" + // q
			"00000003" + // LMOTS type W4
			// C
			"3d46bee8660f8f215d3f96408a7a64cf" +
			"1c4da02b63a55f62c666ef5707a914ce" +
			// y[0..66] — LMOTS_SHA256_N32_W4 has p=67
			"0674e8cb7a55f0c48d484f31f3aa4af9" +
			"719a74f22cf823b94431d01c926e2a76" +
			"bb71226d279700ec81c9e95fb11a0d10" +
			"d065279a5796e265ae17737c44eb8c59" +
			"4508e126a9a7870bf4360820bdeb9a01" +
			"d9693779e416828e75bddd7d8c70d50a" +
			"0ac8ba39810909d445f44cb5bb58de73" +
			"7e60cb4345302786ef2c6b14af212ca1" +
			"9edeaa3bfcfe8baa6621ce88480df237" +
			"1dd37add732c9de4ea2ce0dffa53c926" +
			"49a18d39a50788f4652987f226a1d481" +
			"68205df6ae7c58e049a25d4907edc1aa" +
			"90da8aa5e5f7671773e941d805536021" +
			"5c6b60dd35463cf2240a9c06d694e9cb" +
			"54e7b1e1bf494d0d1a28c0d31acc7516" +
			"1f4f485dfd3cb9578e836ec2dc722f37" +
			"ed30872e07f2b8bd0374eb57d22c614e" +
			"09150f6c0d8774a39a6e168211035dc5" +
			"2988ab46eaca9ec597fb18b4936e66ef" +
			"2f0df26e8d1e34da28cbb3af75231372" +
			"0c7b345434f72d65314328bbb030d0f0" +
			"f6d5e47b28ea91008fb11b05017705a8" +
			"be3b2adb83c60a54f9d1d1b2f476f9e3" +
			"93eb5695203d2ba6ad815e6a111ea293" +
			"dcc21033f9453d49c8e5a6387f588b1e" +
			"a4f706217c151e05f55a6eb7997be09d" +
			"56a326a32f9cba1fbe1c07bb49fa04ce" +
			"cf9df1a1b815483c75d7a27cc88ad1b1" +
			"238e5ea986b53e087045723ce16187ed" +
			"a22e33b2c70709e53251025abde89396" +
			"45fc8c0693e97763928f00b2e3c75af3" +
			"942d8ddaee81b59a6f1f67efda0ef81d" +
			"11873b59137f67800b35e81b01563d18" +
			"7c4a1575a1acb92d087b517a8833383f" +
			"05d357ef4678de0c57ff9f1b2da61dfd" +
			"e5d88318bcdde4d9061cc75c2de3cd47" +
			"40dd7739ca3ef66f1930026f47d9ebaa" +
			"713b07176f76f953e1c2e7f8f271a6ca" +
			"375dbfb83d719b1635a7d8a138919579" +
			"44b1c29bb101913e166e11bd5f34186f" +
			"a6c0a555c9026b256a6860f4866bd6d0" +
			"b5bf90627086c6149133f8282ce6c9b3" +
			"622442443d5eca959d6c14ca8389d12c" +
			"4068b503e4e3c39b635bea245d9d05a2" +
			"558f249c9661c0427d2e489ca5b5dde2" +
			"20a90333f4862aec793223c781997da9" +
			"8266c12c50ea28b2c438e7a379eb106e" +
			"ca0c7fd6006e9bf612f3ea0a454ba3bd" +
			"b76e8027992e60de01e9094fddeb3349" +
			"883914fb17a9621ab929d970d101e45f" +
			"8278c14b032bcab02bd15692d21b6c5c" +
			"204abbf077d465553bd6eda645e6c306" +
			"5d33b10d518a61e15ed0f092c3222628" +
			"1a29c8a0f50cde0a8c66236e29c2f310" +
			"a375cebda1dc6bb9a1a01dae6c7aba8e" +
			"bedc6371a7d52aacb955f83bd6e4f84d" +
			"2949dcc198fb77c7e5cdf6040b0f84fa" +
			"f82808bf985577f0a2acf2ec7ed7c0b0" +
			"ae8a270e951743ff23e0b2dd12e9c3c8" +
			"28fb5598a22461af94d568f29240ba28" +
			"20c4591f71c088f96e095dd98beae456" +
			"579ebbba36f6d9ca2613d1c26eee4d8c" +
			"73217ac5962b5f3147b492e8831597fd" +
			"89b64aa7fde82e1974d2f6779504dc21" +
			"435eb3109350756b9fdabe1c6f368081" +
			"bd40b27ebcb9819a75d7df8bb07bb05d" +
			"b1bab705a4b7e37125186339464ad8fa" +
			"aa4f052cc1272919fde3e025bb64aa8e" +
			"0eb1fcbfcc25acb5f718ce4f7c2182fb" +
			"393a1814b0e942490e52d3bca817b2b2" +
			"6e90d4c9b0cc38608a6cef5eb153af08" +
			"58acc867c9922aed43bb67d7b33acc51" +
			"9313d28d41a5c6fe6cf3595dd5ee63f0" +
			"a4c4065a083590b275788bee7ad875a7" +
			"f88dd73720708c6c6c0ecf1f43bbaada" +
			"e6f208557fdc07bd4ed91f88ce4c0de8" +
			"42761c70c186bfdafafc444834bd3418" +
			"be4253a71eaf41d718753ad07754ca3e" +
			"ffd5960b0336981795721426803599ed" +
			"5b2b7516920efcbe32ada4bcf6c73bd2" +
			"9e3fa152d9adeca36020fdeeee1b7395" +
			"21d3ea8c0da497003df1513897b0f547" +
			"94a873670b8d93bcca2ae47e64424b74" +
			"23e1f078d9554bb5232cc6de8aae9b83" +
			"fa5b9510beb39ccf4b4e1d9c0f19d5e1" +
			"7f58e5b8705d9a6837a7d9bf99cd1338" +
			"7af256a8491671f1f2f22af253bcff54" +
			"b673199bdb7d05d81064ef05f80f0153" +
			"d0be7919684b23da8d42ff3effdb7ca0" +
			"985033f389181f47659138003d712b5e" +
			"c0a614d31cc7487f52de8664916af79c" +
			"98456b2c94a8038083db55391e347586" +
			"2250274a1de2584fec975fb09536792c" +
			"fbfcf6192856cc76eb5b13dc4709e2f7" +
			"301ddff26ec1b23de2d188c999166c74" +
			"e1e14bbc15f457cf4e471ae13dcbdd9c" +
			"50f4d646fc6278e8fe7eb6cb5c94100f" +
			"a870187380b777ed19d7868fd8ca7ceb" +
			"7fa7d5cc861c5bdac98e7495eb0a2cee" +
			"c1924ae979f44c5390ebedddc65d6ec1" +
			"1287d978b8df064219bc5679f7d7b264" +
			"a76ff272b2ac9f2f7cfc9fdcfb6a5142" +
			"8240027afd9d52a79b647c90c2709e06" +
			"0ed70f87299dd798d68f4fadd3da6c51" +
			"d839f851f98f67840b964ebe73f8cec4" +
			"1572538ec6bc131034ca2894eb736b3b" +
			"da93d9f5f6fa6f6c0f03ce43362b8414" +
			"940355fb54d3dfdd03633ae108f3de3e" +
			"bc85a3ff51efeea3bc2cf27e1658f178" +
			"9ee612c83d0f5fd56f7cd071930e2946" +
			"beeecaa04dccea9f97786001475e0294" +
			"bc2852f62eb5d39bb9fbeef75916efe4" +
			"4a662ecae37ede27e9d6eadfdeb8f8b2" +
			"b2dbccbf96fa6dbaf7321fb0e701f4d4" +
			"29c2f4dcd153a2742574126e5eaccc77" +
			"686acf6e3ee48f423766e0fc466810a9" +
			"05ff5453ec99897b56bc55dd49b99114" +
			"2f65043f2d744eeb935ba7f4ef23cf80" +
			"cc5a8a335d3619d781e7454826df720e" +
			"ec82e06034c44699b5f0c44a8787752e" +
			"057fa3419b5bb0e25d30981e41cb1361" +
			"322dba8f69931cf42fad3f3bce6ded5b" +
			"8bfc3d20a2148861b2afc14562ddd27f" +
			"12897abf0685288dcc5c4982f8260268" +
			"46a24bf77e383c7aacab1ab692b29ed8" +
			"c018a65f3dc2b87ff619a633c41b4fad" +
			"b1c78725c1f8f922f6009787b1964247" +
			"df0136b1bc614ab575c59a16d089917b" +
			"d4a8b6f04d95c581279a139be09fcf6e" +
			"98a470a0bceca191fce476f9370021cb" +
			"c05518a7efd35d89d8577c990a5e1996" +
			"1ba16203c959c91829ba7497cffcbb4b" +
			"294546454fa5388a23a22e805a5ca35f" +
			"956598848bda678615fec28afd5da61a" +
			// LMS type for sig[0] (after LMOTS sig): H10
			"00000006" +
			// path[0..9] (10 nodes, 32 bytes each)
			"b326493313053ced3876db9d23714818" +
			"1b7173bc7d042cefb4dbe94d2e58cd21" +
			"a769db4657a103279ba8ef3a629ca84e" +
			"e836172a9c50e51f45581741cf808315" +
			"0b491cb4ecbbabec128e7c81a46e62a6" +
			"7b57640a0a78be1cbf7dd9d419a10cd8" +
			"686d16621a80816bfdb5bdc56211d72c" +
			"a70b81f1117d129529a7570cf79cf52a" +
			"7028a48538ecdd3b38d3d5d62d262465" +
			"95c4fb73a525a5ed2c30524ebb1d8cc8" +
			"2e0c19bc4977c6898ff95fd3d310b0ba" +
			"e71696cef93c6a552456bf96e9d075e3" +
			"83bb7543c675842bafbfc7cdb88483b3" +
			"276c29d4f0a341c2d406e40d4653b7e4" +
			"d045851acf6a0a0ea9c710b805cced46" +
			"35ee8c107362f0fc8d80c14d0ac49c51" +
			"6703d26d14752f34c1c0d2c4247581c1" +
			"8c2cf4de48e9ce949be7c888e9caebe4" +
			"a415e291fd107d21dc1f084b11582082" +
			"49f28f4f7c7e931ba7b3bd0d824a4570" +
			// pub[1]: LMS public key for the bottom tree
			"00000005" + // LMS type H5
			"00000004" + // LMOTS type W8
			"215f83b7ccb9acbcd08db97b0d04dc2b" + // I
			"a1cd035833e0e90059603f26e07ad2aa" + // K
			"d152338e7a5e5984bcd5f7bb4eba40b7" +
			// final_signature: LMS signature under the bottom tree
			"00000004" + // q
			"00000004" + // LMOTS type W8
			// C
			"0eb1ed54a2460d512388cad533138d24" +
			"0534e97b1e82d33bd927d201dfc24ebb" +
			// y[0..33] — LMOTS_SHA256_N32_W8 has p=34
			"11b3649023696f85150b189e50c00e98" +
			"850ac343a77b3638319c347d7310269d" +
			"3b7714fa406b8c35b021d54d4fdada7b" +
			"9ce5d4ba5b06719e72aaf58c5aae7aca" +
			"057aa0e2e74e7dcfd17a0823429db629" +
			"65b7d563c57b4cec942cc865e29c1dad" +
			"83cac8b4d61aacc457f336e6a10b6632" +
			"3f5887bf3523dfcadee158503bfaa89d" +
			"c6bf59daa82afd2b5ebb2a9ca6572a60" +
			"67cee7c327e9039b3b6ea6a1edc7fdc3" +
			"df927aade10c1c9f2d5ff446450d2a39" +
			"98d0f9f6202b5e07c3f97d2458c69d3c" +
			"8190643978d7a7f4d64e97e3f1c4a08a" +
			"7c5bc03fd55682c017e2907eab07e5bb" +
			"2f190143475a6043d5e6d5263471f4ee" +
			"cf6e2575fbc6ff37edfa249d6cda1a09" +
			"f797fd5a3cd53a066700f45863f04b6c" +
			"8a58cfd341241e002d0d2c0217472bf1" +
			"8b636ae547c1771368d9f317835c9b0e" +
			"f430b3df4034f6af00d0da44f4af7800" +
			"bc7a5cf8a5abdb12dc718b559b74cab9" +
			"090e33cc58a955300981c420c4da8ffd" +
			"67df540890a062fe40dba8b2c1c548ce" +
			"d22473219c534911d48ccaabfb71bc71" +
			"862f4a24ebd376d288fd4e6fb06ed870" +
			"5787c5fedc813cd2697e5b1aac1ced45" +
			"767b14ce88409eaebb601a93559aae89" +
			"3e143d1c395bc326da821d79a9ed41dc" +
			"fbe549147f71c092f4f3ac522b5cc572" +
			"90706650487bae9bb5671ecc9ccc2ce5" +
			"1ead87ac01985268521222fb9057df7e" +
			"d41810b5ef0d4f7cc67368c90f573b1a" +
			"c2ce956c365ed38e893ce7b2fae15d36" +
			"85a3df2fa3d4cc098fa57dd60d2c9754" +
			"a8ade980ad0f93f6787075c3f680a2ba" +
			"1936a8c61d1af52ab7e21f416be09d2a" +
			"8d64c3d3d8582968c2839902229f85ae" +
			"e297e717c094c8df4a23bb5db658dd37" +
			"7bf0f4ff3ffd8fba5e383a48574802ed" +
			"545bbe7a6b4753533353d73706067640" +
			"135a7ce517279cd683039747d218647c" +
			"86e097b0daa2872d54b8f3e508598762" +
			"9547b830d8118161b65079fe7bc59a99" +
			"e9c3c7380e3e70b7138fe5d9be255150" +
			"2b698d09ae193972f27d40f38dea264a" +
			"0126e637d74ae4c92a6249fa103436d3" +
			"eb0d4029ac712bfc7a5eacbdd7518d6d" +
			"4fe903a5ae65527cd65bb0d4e9925ca2" +
			"4fd7214dc617c150544e423f450c99ce" +
			"51ac8005d33acd74f1bed3b17b7266a4" +
			"a3bb86da7eba80b101e15cb79de9a207" +
			"852cf91249ef480619ff2af8cabca831" +
			"25d1faa94cbb0a03a906f683b3f47a97" +
			"c871fd513e510a7a25f283b196075778" +
			"496152a91c2bf9da76ebe089f4654877" +
			"f2d586ae7149c406e663eadeb2b5c7e8" +
			"2429b9e8cb4834c83464f079995332e4" +
			"b3c8f5a72bb4b8c6f74b0d45dc6c1f79" +
			"952c0b7420df525e37c15377b5f09843" +
			"19c3993921e5ccd97e097592064530d3" +
			"3de3afad5733cbe7703c5296263f7734" +
			"2efbf5a04755b0b3c997c4328463e84c" +
			"aa2de3ffdcd297baaaacd7ae646e44b5" +
			"c0f16044df38fabd296a47b3a838a913" +
			"982fb2e370c078edb042c84db34ce36b" +
			"46ccb76460a690cc86c302457dd1cde1" +
			"97ec8075e82b393d542075134e2a17ee" +
			"70a5e187075d03ae3c853cff60729ba4" +
			// LMS type for final sig: H5
			"00000005" +
			// path[0..4] (5 nodes, 32 bytes each)
			"4de1f6965bdabc676c5a4dc7c35f97f8" +
			"2cb0e31c68d04f1dad96314ff09e6b3d" +
			"e96aeee300d1f68bf1bca9fc58e40323" +
			"36cd819aaf578744e50d1357a0e42867" +
			"04d341aa0a337b19fe4bc43c2e79964d" +
			"4f351089f2e0e41c7c43ae0d49e7f404" +
			"b0f75be80ea3af098c9752420a8ac0ea" +
			"2bbb1f4eeba05238aef0d8ce63f0c6e5" +
			"e4041d95398a6f7f3e0ee97cc1591849" +
			"d4ed236338b147abde9f51ef9fd4e1c1"
	)

	msg, err := hex.DecodeString(msgHex)
	assert.NoError(t, err)
	pubBytes, err := hex.DecodeString(pubHex)
	assert.NoError(t, err)
	sigBytes, err := hex.DecodeString(sigHex)
	assert.NoError(t, err)

	// Sanity-check the byte lengths against the chosen parameter sets.
	assert.Equal(t, 60, len(pubBytes))
	assert.Equal(t, 3860, len(sigBytes))

	pub, err := hss.HssPublicKeyFromBytes(pubBytes)
	assert.NoError(t, err)
	sig, err := hss.HssSignatureFromBytes(sigBytes)
	assert.NoError(t, err)

	assert.True(t, pub.Verify(msg, sig), "RFC 8554 §F Test Case 2 failed to verify")

	// Flipping a bit in the signature must cause verification to fail.
	tampered := make([]byte, len(sigBytes))
	copy(tampered, sigBytes)
	tampered[len(tampered)-1] ^= 0x01
	sig2, err := hss.HssSignatureFromBytes(tampered)
	assert.NoError(t, err)
	assert.False(t, pub.Verify(msg, sig2))
}
