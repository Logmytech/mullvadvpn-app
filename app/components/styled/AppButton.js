// @flow
import * as React from 'react';
import { Text, Component } from 'reactxp';
import { Button } from './Button';
import styles from './AppButtonStyles';
import blurStyles from './BlurAppButtonStyles';

export class Label extends Text {}

class BaseButton extends Component {
  props: {
    children?: React.Node,
    disabled: boolean,
  };

  state = { hovered: false };

  textStyle = () => this.state.hovered ? styles.white80 : styles.white;
  iconStyle = () => this.state.hovered ? styles.white80 : styles.white;
  backgroundStyle = () => this.state.hovered ? styles.white80 : styles.white;

  onHoverStart = () => !this.props.disabled ? this.setState({ hovered: true }) : null;
  onHoverEnd = () => !this.props.disabled ? this.setState({ hovered: false }) : null;
  render() {
    const { children, ...otherProps } = this.props;
    return (
      <Button style={[ styles.common, this.backgroundStyle() ]}
        onHoverStart={this.onHoverStart}
        onHoverEnd={this.onHoverEnd}
        {...otherProps}>
        {
          React.Children.map(children, (node) => {
            if (React.isValidElement(node)) {
              let updatedProps = {};

              if(node.type.name === 'Label') {
                updatedProps = { style: [styles.label, this.textStyle()]};
              }

              if(node.type.name === 'Img') {
                updatedProps = { tintColor:'currentColor', style: [styles.icon, this.iconStyle()]};
              }

              return React.cloneElement(node, updatedProps);
            } else {
              return <Label style={[styles.label, this.textStyle()]}>{children}</Label>;
            }
          })
        }
      </Button>
    );
  }
}

export class RedButton extends BaseButton {
  backgroundStyle = () => this.state.hovered ? styles.redHover : styles.red;
}

export class GreenButton extends BaseButton {
  backgroundStyle = () => this.state.hovered ? styles.greenHover : styles.green;
}

export class BlueButton extends BaseButton {
  backgroundStyle = () => this.state.hovered ? styles.blueHover : styles.blue;
}

export class TransparentButton extends BaseButton {
  backgroundStyle = () => this.state.hovered ? blurStyles.transparentHover : blurStyles.transparent;
}

export class RedTransparentButton extends BaseButton {
  backgroundStyle = () => this.state.hovered ? blurStyles.redTransparentHover : blurStyles.redTransparent;
}