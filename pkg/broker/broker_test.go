/*
Copyright 2018 Pressinfra SRL.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package broker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	giteasdk "code.gitea.io/sdk/gitea"
	"golang.org/x/net/context"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/presslabs/gitea-service-broker/pkg/cmd/options"
	"github.com/presslabs/gitea-service-broker/pkg/internal/vendors/gitea"
)

func createAPIRequest(body interface{}, query url.Values, u, method string) (request *http.Request, err error) {
	if u == "" {
		err = errors.New("url must not be empty")
		return
	}

	parsedURL, err := url.Parse(u)
	if err != nil {
		return nil, err
	}

	jsonBody := []byte("")

	switch method {
	case "PUT", "POST", "PATCH":
		jsonBody, err = json.Marshal(body)
		if err != nil {
			return
		}
	case "GET", "DELETE":
		break
	default:
		return nil, errors.New("unexpected method value")
	}

	parsedURL.RawQuery = query.Encode()

	request, err = http.NewRequest(method, parsedURL.String(), bytes.NewBuffer(jsonBody))
	if err != nil {
		return
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Broker-API-Version", "2.14")
	request.SetBasicAuth(options.Username, options.Password)

	return
}

var _ = Describe("Gitea Service Broker", func() {
	var (
		// stop channel for controller manager
		stop chan struct{}
		// gitea fake client
		giteaFakeClient *gitea.FakeClient
		// controller k8s client
		c client.Client

		server                              *http.Server
		instanceID, bindingID               string
		instanceSecretKey, bindingSecretKey client.ObjectKey
		request                             *http.Request
		recorder                            *httptest.ResponseRecorder
		secretsSelector                     labels.Selector
	)

	createInstanceSecret := func() {
		// Create instance Secret
		err := c.Create(context.TODO(), &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{
					"app.kubernetes.io/component": "service-instance",
				},
				Name:      instanceSecretKey.Name,
				Namespace: instanceSecretKey.Namespace,
			},
			Data: map[string][]byte{
				"repository_owner": []byte(repo.Owner.UserName),
				"repository_name":  []byte(repo.Name),
				"migrate_url":      []byte(""),
			},
		})
		Expect(err).To(Succeed())
	}
	createBindingSecret := func() {
		err := c.Create(context.TODO(), &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: bindingSecretKey.Namespace,
				Name:      bindingSecretKey.Name,
				Labels: map[string]string{
					"app.kubernetes.io/name":      "gitea-service-broker",
					"app.kubernetes.io/component": "service-binding",
				},
			},
			StringData: map[string]string{
				"instance_id": instanceID,
				"title":       deployKey.Title,
				"public_key":  publicKey,
				"fingerprint": publicKeyFingerprint,
			},
		})
		Expect(err).To(Succeed())
	}

	BeforeEach(func() {
		mgr, err := manager.New(cfg, manager.Options{})
		Expect(err).NotTo(HaveOccurred())

		// create new k8s client
		c, err = client.New(cfg, client.Options{})
		Expect(err).To(Succeed())

		giteaFakeClient = gitea.NewFakeClient("https://gitea.presslabs.net", "token")
		options.Username = "username"
		options.Password = "password"

		options.OperationTimeout = 0

		instanceID = strconv.Itoa(int(rand.Int31()))
		bindingID = strconv.Itoa(int(rand.Int31()))
		instanceSecretKey = client.ObjectKey{
			Name:      fmt.Sprintf("gsb-instance-%s", instanceID),
			Namespace: options.Namespace,
		}
		bindingSecretKey = client.ObjectKey{
			Name:      fmt.Sprintf("gsb-binding-%s", bindingID),
			Namespace: options.Namespace,
		}
		secretsSelector, err = metav1.LabelSelectorAsSelector(
			&metav1.LabelSelector{
				MatchLabels: labels.Set{
					"app.kubernetes.io/name": "gitea-service-broker",
				},
			},
		)
		Expect(err).To(Succeed())

		server = SetupAPIServer(giteaFakeClient, mgr).HTTPServer
		recorder = httptest.NewRecorder()

		stop = StartTestManager(mgr)
	})

	AfterEach(func() {
		time.Sleep(1 * time.Second)

		// delete created secrets

		secrets := &corev1.SecretList{}

		err := c.List(context.TODO(), &client.ListOptions{LabelSelector: secretsSelector}, secrets)
		Expect(err).To(Succeed())

		for _, secret := range secrets.Items {
			err = c.Delete(context.TODO(), &secret)
			Expect(err).To(Succeed())
		}
		close(stop)
	})

	When("provisioning an instance", func() {
		var (
			err    error
			body   map[string]interface{}
			apiURL string
		)
		BeforeEach(func() {
			body = map[string]interface{}{
				"service_id": options.ServiceID,
				"plan_id":    options.DefaultPlanID,
				"parameters": map[string]string{
					"repository_name":  repo.Name,
					"repository_owner": repo.Owner.UserName,
				},
			}
			apiURL = fmt.Sprintf("/v2/service_instances/%s", instanceID)
			request, err = createAPIRequest(body, url.Values{}, apiURL, "PUT")
			Expect(err).To(Succeed())
		})
		Context("and instance ID hasn't been used before", func() {
			Context("and OrganizationPolicy is reuse-or-create", func() {
				BeforeEach(func() {
					options.OrganizationPolicy = options.OrgPolicyReuseOrCreate

					giteaFakeClient.AdminCreateRepoExpectedCalls = append(
						giteaFakeClient.AdminCreateRepoExpectedCalls, createRepoCall,
					)
					giteaFakeClient.AdminCreateOrgExpectedCalls = append(
						giteaFakeClient.AdminCreateOrgExpectedCalls, createOrgCall,
					)
				})

				It("returns successful response", func() {
					server.Handler.ServeHTTP(recorder, request)

					Expect(recorder.Code).To(Equal(http.StatusCreated), recorder.Body.String())
				})
				It("creates instance secret", func() {
					server.Handler.ServeHTTP(recorder, request)

					instanceSecret := &corev1.Secret{}
					err := c.Get(context.TODO(), instanceSecretKey, instanceSecret)
					Expect(err).To(Succeed())
					Expect(instanceSecret.Labels["app.kubernetes.io/component"]).To(Equal("service-instance"))
				})
			})

			Context("and OrganizationPolicy is reuse-or-fail", func() {
				BeforeEach(func() {
					options.OrganizationPolicy = options.OrgPolicyReuseOrFail

					request, err = createAPIRequest(body, url.Values{}, apiURL, "PUT")
					Expect(err).To(Succeed())
				})
				Context("and organization doesn't exist", func() {
					BeforeEach(func() {
						giteaFakeClient.AdminCreateRepoExpectedCalls = append(
							giteaFakeClient.AdminCreateRepoExpectedCalls, createRepoCallOrgDoesNotExist,
						)
					})
					It("returns an error", func() {
						server.Handler.ServeHTTP(recorder, request)

						Expect(recorder.Code).To(Equal(http.StatusBadRequest), recorder.Body.String())
						response := &map[string]string{}
						err := json.Unmarshal(recorder.Body.Bytes(), response)
						Expect(err).To(Succeed())
						Expect(response).To(Equal(&map[string]string{
							"description": "organization does not exist",
						}))
					})
					It("doesn't create a secret", func() {
						secrets := &corev1.SecretList{}

						err = c.List(context.TODO(), &client.ListOptions{LabelSelector: secretsSelector}, secrets)
						Expect(err).To(Succeed())

						Expect(secrets.Items).To(BeEmpty())
					})
				})
				Context("and organization exists", func() {
					BeforeEach(func() {
						giteaFakeClient.AdminCreateRepoExpectedCalls = append(
							giteaFakeClient.AdminCreateRepoExpectedCalls, createRepoCall,
						)
					})
					It("returns successful response", func() {
						server.Handler.ServeHTTP(recorder, request)

						Expect(recorder.Code).To(Equal(http.StatusCreated), recorder.Body.String())
					})
					It("creates instance secret", func() {
						server.Handler.ServeHTTP(recorder, request)

						instanceSecret := &corev1.Secret{}
						err := c.Get(context.TODO(), instanceSecretKey, instanceSecret)
						Expect(err).To(Succeed())
						Expect(instanceSecret.Labels["app.kubernetes.io/component"]).To(Equal("service-instance"))
					})
				})
			})
		})

		Context("and instance ID has been used before", func() {
			BeforeEach(createInstanceSecret)
			BeforeEach(func() {
				giteaFakeClient.AdminCreateOrgExpectedCalls = append(
					giteaFakeClient.AdminCreateOrgExpectedCalls, createOrgCallOrgAlreadyExists,
				)
			})

			Context("and there is an existing valid instance", func() {
				Context("with the same params", func() {
					BeforeEach(func() {
						giteaFakeClient.GetRepoExpectedCalls = append(giteaFakeClient.GetRepoExpectedCalls, getRepoCall)
					})

					It("checks for existing instance, and doesn't reprovision", func() {
						server.Handler.ServeHTTP(recorder, request)

						Expect(giteaFakeClient.GetRepoExpectedCalls).To(BeEmpty())
						// if it would reprovision a panic would be thrown because there is no expected create call
					})
					It("returns successful response", func() {
						server.Handler.ServeHTTP(recorder, request)

						Expect(recorder.Code).To(Equal(http.StatusCreated), recorder.Body.String())
					})
				})

				Context("with different params", func() {
					BeforeEach(func() {
						params := body["parameters"].(map[string]string)
						params["repository_name"] = "different"
						body["parameters"] = params

						request, err = createAPIRequest(body, url.Values{}, apiURL, "PUT")
						Expect(err).To(Succeed())
					})
					It("returns already exists error response", func() {
						server.Handler.ServeHTTP(recorder, request)

						Expect(recorder.Code).To(Equal(http.StatusConflict), recorder.Body.String())
					})
				})
			})
			Context("and there is no existing Gitea instance", func() {
				BeforeEach(func() {
					getRepoCall := func(owner string, name string) (*giteasdk.Repository, error) {
						defer GinkgoRecover()
						Expect(owner).To(Equal(repo.Owner.UserName))
						Expect(name).To(Equal(repo.Name))

						return nil, errors.New("404 Not Found")
					}
					giteaFakeClient.GetRepoExpectedCalls = append(giteaFakeClient.GetRepoExpectedCalls, getRepoCall)
				})
				Context("and request is made with same secret params", func() {
					BeforeEach(func() {
						giteaFakeClient.AdminCreateRepoExpectedCalls = append(
							giteaFakeClient.AdminCreateRepoExpectedCalls, createRepoCall,
						)
					})
					It("returns successful response", func() {
						server.Handler.ServeHTTP(recorder, request)

						Expect(recorder.Code).To(Equal(http.StatusCreated), recorder.Body.String())
						response := &map[string]string{}
						err := json.Unmarshal(recorder.Body.Bytes(), response)
						Expect(err).To(Succeed())
						Expect(response).To(Equal(&map[string]string{
							"dashboard_url": repo.HTMLURL,
						}))
					})
				})
			})
		})
		Context("with bad request", func() {
			Context("and a repository name is not specified", func() {
				BeforeEach(func() {
					params := body["parameters"].(map[string]string)
					params["repository_name"] = ""
					body["parameters"] = params

					request, err = createAPIRequest(body, url.Values{}, apiURL, "PUT")
					Expect(err).To(Succeed())
				})
				It("returns an error", func() {
					server.Handler.ServeHTTP(recorder, request)

					Expect(recorder.Code).To(Equal(http.StatusBadRequest), recorder.Body.String())
					response := &map[string]string{}
					err := json.Unmarshal(recorder.Body.Bytes(), response)
					Expect(err).To(Succeed())
					Expect(response).To(Equal(&map[string]string{
						"description": "`repository_name` must be specified",
					}))
				})
				It("doesn't create a secret", func() {
					secrets := &corev1.SecretList{}

					err = c.List(context.TODO(), &client.ListOptions{LabelSelector: secretsSelector}, secrets)
					Expect(err).To(Succeed())

					Expect(secrets.Items).To(BeEmpty())
				})
			})
			Context("and no user or organization is specified", func() {
				BeforeEach(func() {
					params := body["parameters"].(map[string]string)
					params["repository_owner"] = ""
					body["parameters"] = params

					request, err = createAPIRequest(body, url.Values{}, apiURL, "PUT")
					Expect(err).To(Succeed())
				})
				It("returns an error", func() {
					server.Handler.ServeHTTP(recorder, request)

					Expect(recorder.Code).To(Equal(http.StatusBadRequest), recorder.Body.String())
					response := &map[string]string{}
					err := json.Unmarshal(recorder.Body.Bytes(), response)
					Expect(err).To(Succeed())
					Expect(response).To(Equal(&map[string]string{
						"description": "you must specify a `repository_owner`",
					}))
				})
				It("doesn't create a secret", func() {
					secrets := &corev1.SecretList{}

					err = c.List(context.TODO(), &client.ListOptions{LabelSelector: secretsSelector}, secrets)
					Expect(err).To(Succeed())

					Expect(secrets.Items).To(BeEmpty())
				})
			})
		})
	})
	When("binding an instance", func() {
		var (
			err    error
			body   map[string]interface{}
			apiURL string
		)
		BeforeEach(func() {
			body = map[string]interface{}{
				"service_id": options.ServiceID,
				"plan_id":    options.DefaultPlanID,
			}

			apiURL = fmt.Sprintf("/v2/service_instances/%s/service_bindings/%s", instanceID, bindingID)
			request, err = createAPIRequest(body, url.Values{}, apiURL, "PUT")
			Expect(err).To(Succeed())
		})
		Context("and a service instance exists", func() {
			BeforeEach(func() {
				instanceSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: instanceSecretKey.Namespace,
						Name:      instanceSecretKey.Name,
						Labels: map[string]string{
							"app.kubernetes.io/name":      "gitea-service-broker",
							"app.kubernetes.io/component": "service-instance",
						},
					},
					StringData: map[string]string{
						"repository_name":  repo.Name,
						"repository_owner": repo.Owner.UserName,
					},
				}

				err = c.Create(context.TODO(), instanceSecret)
				Expect(err).To(Succeed())
			})
		})

		Context("and an instance secret does not exist", func() {
			It("returns an instance does not exist error response", func() {
				server.Handler.ServeHTTP(recorder, request)

				Expect(recorder.Code).To(Equal(http.StatusNotFound), recorder.Body.String())
				response := map[string]string{}
				err := json.Unmarshal(recorder.Body.Bytes(), &response)
				Expect(err).To(Succeed())
				Expect(response).To(Equal(map[string]string{
					"description": "instance cannot be fetched",
				}))
			})
		})
	})
	When("deprovisioning an instance", func() {
		var (
			err         error
			apiURL      string
			queryParams map[string][]string
		)
		BeforeEach(func() {
			queryParams = map[string][]string{
				"service_id": {options.ServiceID},
				"plan_id":    {options.DefaultPlanID},
			}
			apiURL = fmt.Sprintf("/v2/service_instances/%s", instanceID)
			request, err = createAPIRequest("", queryParams, apiURL, "DELETE")
			Expect(err).To(Succeed())
		})

		Context("and the service instance secret exists", func() {
			BeforeEach(createInstanceSecret)

			Context("and the repository exists", func() {
				BeforeEach(func() {
					deleteRepoCall := func(owner string, repoName string) error {
						defer GinkgoRecover()
						Expect(owner).To(Equal(repo.Owner.UserName))
						Expect(repoName).To(Equal(repo.Name))

						return nil
					}
					giteaFakeClient.DeleteRepoExpectedCalls = append(
						giteaFakeClient.DeleteRepoExpectedCalls, deleteRepoCall,
					)
				})
				It("returns a successful response", func() {
					server.Handler.ServeHTTP(recorder, request)

					Expect(recorder.Code).To(Equal(http.StatusOK), recorder.Body.String())
				})
				It("deletes the repository", func() {
					server.Handler.ServeHTTP(recorder, request)

					Expect(giteaFakeClient.DeleteRepoExpectedCalls).To(BeEmpty())
				})
				It("deletes the service instance secret", func() {
					server.Handler.ServeHTTP(recorder, request)

					err := c.Get(context.TODO(), instanceSecretKey, &corev1.Secret{})
					Expect(err).To(Not(Succeed()))
					Expect(apierrors.IsNotFound(err)).To(BeTrue())
				})
			})
			Context("and the repository doesn't exist", func() {
				BeforeEach(func() {
					deleteRepoCall := func(owner string, repoName string) error {
						defer GinkgoRecover()
						Expect(owner).To(Equal(repo.Owner.UserName))
						Expect(repoName).To(Equal(repo.Name))

						return errors.New("404 Not Found")
					}
					giteaFakeClient.DeleteRepoExpectedCalls = append(
						giteaFakeClient.DeleteRepoExpectedCalls, deleteRepoCall,
					)
				})
				It("returns a successful response", func() {
					server.Handler.ServeHTTP(recorder, request)

					Expect(recorder.Code).To(Equal(http.StatusOK), recorder.Body.String())
				})
				It("attempts to delete the repository", func() {
					server.Handler.ServeHTTP(recorder, request)

					Expect(giteaFakeClient.DeleteRepoExpectedCalls).To(BeEmpty())
				})
				It("deletes the service instance secret", func() {
					server.Handler.ServeHTTP(recorder, request)

					err := c.Get(context.TODO(), instanceSecretKey, &corev1.Secret{})
					Expect(err).To(Not(Succeed()))
					Expect(apierrors.IsNotFound(err)).To(BeTrue())
				})
			})

		})
		Context("and the service instance secret doesn't exist", func() {
			It("returns a service instance gone error", func() {
				server.Handler.ServeHTTP(recorder, request)

				Expect(recorder.Code).To(Equal(http.StatusGone), recorder.Body.String())
			})
		})
	})
	When("unbinding an instance", func() {
		var (
			err         error
			apiURL      string
			queryParams map[string][]string
		)
		BeforeEach(func() {
			createInstanceSecret()

			queryParams = map[string][]string{
				"service_id": {options.ServiceID},
				"plan_id":    {options.DefaultPlanID},
			}
			apiURL = fmt.Sprintf("/v2/service_instances/%s/service_bindings/%s", instanceID, bindingID)
			request, err = createAPIRequest("", queryParams, apiURL, "DELETE")
			Expect(err).To(Succeed())
		})
		Context("and the service binding secret exists", func() {
			BeforeEach(createBindingSecret)
			Context("and the deploy key exists", func() {
				BeforeEach(func() {
					giteaFakeClient.ListDeployKeysExpectedCalls = append(
						giteaFakeClient.ListDeployKeysExpectedCalls, listDeployKeysCall,
					)
					deleteDeployKeyCall := func(user string, repoName string, id int64) error {
						defer GinkgoRecover()
						Expect(user).To(Equal(repo.Owner.UserName))
						Expect(repoName).To(Equal(repo.Name))
						Expect(id).To(Equal(int64(1234)))

						return nil
					}
					giteaFakeClient.DeleteDeployKeyExpectedCalls = append(
						giteaFakeClient.DeleteDeployKeyExpectedCalls, deleteDeployKeyCall,
					)
				})
				It("returns a successful response", func() {
					server.Handler.ServeHTTP(recorder, request)

					Expect(recorder.Code).To(Equal(http.StatusOK), recorder.Body.String())
				})
				It("deletes the deploy key", func() {
					server.Handler.ServeHTTP(recorder, request)

					Expect(giteaFakeClient.DeleteDeployKeyExpectedCalls).To(BeEmpty())
				})
				It("deletes the service binding secret", func() {
					server.Handler.ServeHTTP(recorder, request)

					err := c.Get(context.TODO(), bindingSecretKey, &corev1.Secret{})
					Expect(err).To(Not(Succeed()))
					Expect(apierrors.IsNotFound(err)).To(BeTrue())
				})
			})
			Context("and the deploy key doesn't exist", func() {
				BeforeEach(func() {
					giteaFakeClient.ListDeployKeysExpectedCalls = append(
						giteaFakeClient.ListDeployKeysExpectedCalls, listDeployKeysNotFoundCall,
					)
				})
				It("returns a successful response", func() {
					server.Handler.ServeHTTP(recorder, request)

					Expect(recorder.Code).To(Equal(http.StatusOK), recorder.Body.String())
				})
				It("deletes the deploy key", func() {
					server.Handler.ServeHTTP(recorder, request)

					Expect(giteaFakeClient.DeleteDeployKeyExpectedCalls).To(BeEmpty())
				})
				It("deletes the service binding secret", func() {
					server.Handler.ServeHTTP(recorder, request)

					err := c.Get(context.TODO(), bindingSecretKey, &corev1.Secret{})
					Expect(err).To(Not(Succeed()))
					Expect(apierrors.IsNotFound(err)).To(BeTrue())
				})
			})
		})
		Context("and the service binding secret doesn't exist", func() {
			It("returns a service binding gone error", func() {
				server.Handler.ServeHTTP(recorder, request)

				Expect(recorder.Code).To(Equal(http.StatusGone), recorder.Body.String())
			})
		})
	})
	When("getting an instance", func() {
		var (
			err         error
			apiURL      string
			queryParams map[string][]string
		)
		BeforeEach(func() {
			queryParams = map[string][]string{
				"service_id": {options.ServiceID},
				"plan_id":    {options.DefaultPlanID},
			}
			apiURL = fmt.Sprintf("/v2/service_instances/%s", instanceID)
			request, err = createAPIRequest("", queryParams, apiURL, "GET")
			Expect(err).To(Succeed())
		})
		Context("and the instance secret exists", func() {
			BeforeEach(createInstanceSecret)
			Context("and the repository exists", func() {
				BeforeEach(func() {
					giteaFakeClient.GetRepoExpectedCalls = append(
						giteaFakeClient.GetRepoExpectedCalls, getRepoCall,
					)
				})
				It("returns a successful response", func() {
					server.Handler.ServeHTTP(recorder, request)

					Expect(recorder.Code).To(Equal(http.StatusOK), recorder.Body.String())
					response := &map[string]string{}
					err := json.Unmarshal(recorder.Body.Bytes(), response)
					Expect(err).To(Succeed())
					Expect(response).To(Equal(&map[string]string{
						"service_id":    options.ServiceID,
						"plan_id":       options.DefaultPlanID,
						"dashboard_url": repo.HTMLURL,
					}))
				})
				It("actually checks the repository", func() {
					server.Handler.ServeHTTP(recorder, request)

					Expect(giteaFakeClient.GetRepoExpectedCalls).To(BeEmpty())
				})
			})
			Context("and the repository doesn't exist", func() {
				BeforeEach(func() {
					getRepoCall := func(owner string, name string) (*giteasdk.Repository, error) {
						defer GinkgoRecover()
						Expect(owner).To(Equal(repo.Owner.UserName))
						Expect(name).To(Equal(repo.Name))

						return nil, errors.New("404 Not Found")
					}

					giteaFakeClient.GetRepoExpectedCalls = append(
						giteaFakeClient.GetRepoExpectedCalls, getRepoCall,
					)
				})
				It("returns a not found error response", func() {
					server.Handler.ServeHTTP(recorder, request)

					Expect(recorder.Code).To(Equal(http.StatusNotFound), recorder.Body.String())
					response := &map[string]string{}
					err := json.Unmarshal(recorder.Body.Bytes(), response)
					Expect(err).To(Succeed())
					Expect(response).To(Equal(&map[string]string{
						"description": "instance cannot be fetched",
					}))
				})
			})
		})
		Context("and the instance secret doesn't exist", func() {
			It("returns a not found error response", func() {
				server.Handler.ServeHTTP(recorder, request)

				Expect(recorder.Code).To(Equal(http.StatusNotFound), recorder.Body.String())
				response := &map[string]string{}
				err := json.Unmarshal(recorder.Body.Bytes(), response)
				Expect(err).To(Succeed())
				Expect(response).To(Equal(&map[string]string{
					"description": "instance cannot be fetched",
				}))
			})
		})
	})
})
