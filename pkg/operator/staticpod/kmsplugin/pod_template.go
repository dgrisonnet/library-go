package kmsplugin

import (
	"bytes"
	"text/template"
)

type awsPluginTemplate struct {
	TargetNamespace string
	PluginImage     string
	KeyARN          string
	Region          string
	Listen          string
}

func GenerateAWSPluginTemplate(targetNamespace, image, keyARN, region, listen string) (string, error) {
	rawAWSPluginManifest, err := asset("assets/aws-kms-plugin-pod.yaml")
	if err != nil {
		return "", err
	}

	tmplVal := awsPluginTemplate{
		TargetNamespace: targetNamespace,
		PluginImage:     image,
		KeyARN:          keyARN,
		Region:          region,
		Listen:          listen,
	}
	tmpl, err := template.New("aws-plugin").Parse(string(rawAWSPluginManifest))
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, tmplVal)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}
