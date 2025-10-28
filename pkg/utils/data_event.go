package utils

import "github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"

type IDataEvent interface {
	GetData() datasource.Data
	GetDatasource() datasource.DataSource
}

type DataEvent struct {
	Data       datasource.Data
	DataSource datasource.DataSource
}

func (e *DataEvent) GetData() datasource.Data {
	return e.Data
}

func (e *DataEvent) GetDatasource() datasource.DataSource {
	return e.DataSource
}
