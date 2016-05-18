# coding:utf-8
# Copyright 2016 Huawei Technologies Co. Ltd. All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo_config import cfg
from oslo_log import log as logging

from networking_huawei.common.ac.client.restclient import RestClient


LOG = logging.getLogger(__name__)


class RESTService(object):

    def __init__(self):
        self.host = cfg.CONF.ml2_huawei_ac.host
        self.port = cfg.CONF.ml2_huawei_ac.port
        self.serviceName = cfg.CONF.ml2_huawei_ac.service_name
        self.url = '%s%s%s%s' % ("http://", self.host, ":", str(self.port))

    def requestREST(self, method, url, id, body,
                    callBack=None):
        client = RestClient()
        result = client.send(
            self.host, self.port, method, url,
            id, body, callBack)
        return result

    def requestService(self, method, url, id, body, isNeedServiceName=None,
                       callBack=None):
        LOG.debug('Request Service has been called.')
        client = RestClient()
        if isNeedServiceName is True:
            for key in body:
                body[key]["serviceName"] = self.serviceName
        self.__requestServiceParams__ = {
            "method": method,
            "url": '%s%s' % (self.url, url),
            "body": body,
            "id": id,
            "callBack": callBack
        }
        result = self.__doRequestSerive__(data='', status='', reason='')
        if client.http_success(result):
            LOG.debug('AC: request is success.')
        else:
            LOG.debug('AC: request failed.')

    def __doRequestSerive__(self, data, status, reason):

        result = self.requestREST(
            self.__requestServiceParams__['method'],
            self.__requestServiceParams__['url'],
            self.__requestServiceParams__['id'],
            self.__requestServiceParams__['body'],
            self.__requestServiceParams__['callBack'])

        return result
