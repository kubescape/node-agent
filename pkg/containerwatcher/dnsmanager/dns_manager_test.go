package dnsmanager

// func TestDNSManager(t *testing.T) {
// 	cfg := config.Config{
// 		InitialDelay:     1 * time.Second,
// 		MaxSniffingTime:  5 * time.Minute,
// 		UpdateDataPeriod: 20 * time.Second,
// 	}

// 	ctx := context.TODO()
// 	k8sClient := &k8sclient.K8sClientMock{}
// 	storageClient := &storage.StorageHttpClientMock{}
// 	nm := CreateDNSManager(ctx, cfg, k8sClient, storageClient, "test")

// 	container := &containercollection.Container{
// 		K8s: containercollection.K8sMetadata{
// 			BasicK8sMetadata: types.BasicK8sMetadata{
// 				Namespace:     "ns",
// 				PodName:       "pod",
// 				ContainerName: "cont",
// 			},
// 		},
// 		Runtime: containercollection.RuntimeMetadata{
// 			BasicRuntimeMetadata: types.BasicRuntimeMetadata{
// 				ContainerID: "5fff6a395ce4e6984a9447cc6cfb09f473eaf278498243963fcc944889bc8400",
// 			},
// 		},
// 	}
// 	nm.ContainerCallback(containercollection.PubSubEvent{
// 		Type:      containercollection.EventTypeAddContainer,
// 		Container: container,
// 	})

// 	dnsEvent := &tracerdnstype.Event{
// 		Qr:      tracerdnstype.DNSPktTypeResponse,
// 		QType:   "A",
// 		DNSName: "google.com",
// 		Addresses: []string{
// 			"15.52.34.53",
// 			"12.52.34.53",
// 		},
// 	}

// 	nm.SaveNetworkEvent("test", *dnsEvent)
// 	time.Sleep(12 * time.Second)

// 	nm.ContainerCallback(containercollection.PubSubEvent{
// 		Type:      containercollection.EventTypeRemoveContainer,
// 		Container: container,
// 	})

// 	assert.Equal(t, 2, len(nm.addressToDomainMap.Keys()))
// }
